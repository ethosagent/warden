# Control plane

Warden ships one binary with two roles:

- **Worker** (`warden run`) — the data plane. Sits in front of an agent,
  enforces allow/deny policy on every call, swaps secrets at the edge.
- **Control plane** (`warden control-plane`) — serves allow/deny policy to many
  workers and aggregates their analytics into a fleet dashboard.

They are **separate processes that only ever talk over HTTPS**, so you can run
them together on one host today and split the control plane onto its own host
later by *moving a service* — no code change.

Before a control plane serves real traffic, work through the [production readiness
checklist](production-readiness.md).

```
                 ┌──────────────────────────────┐
   GET /policy   │      warden control-plane     │   POST /central/ingest
  ◀──────────────┤  • serves allow/deny policy   ├──────────────▶
   (hot-reloaded)│  • ingests fleet analytics    │   (events)
                 │  • fleet dashboard :7070      │
                 └──────────────────────────────┘
                        ▲                ▲
              ┌─────────┘                └─────────┐
        warden run (worker-1)            warden run (worker-2)
        agent-1 ──▶ egress               agent-2 ──▶ egress
```

## The boundary: policy only, never secrets

The control plane serves an explicit allow/deny wire type — it **cannot** send
secrets, judge config, or anything else, even if `config.Policy` grows new
fields later (the guarantee is structural, in code, not a struct tag). Secrets
stay on each worker and are injected at that worker's edge. A compromised
control plane still cannot leak a single real credential, because it never holds
one.

## Trust (HTTPS)

Workers require HTTPS for the policy pull. The control plane mints its server
cert from a CA you give it (`--ca-cert`/`--ca-key`); in the example that's the
same proxy CA the workers already use. Each worker trusts it via
`controlPlane.caCert` / `central.caCert`, which adds that CA to a
**per-connection** pool only — the worker's upstream TLS trust is unchanged.

## Worker ↔ control plane: the only interactions

Every connection is **worker-initiated** (the worker always dials out, so no
inbound port is opened on the worker), and the control plane **never** calls into
a worker. There are exactly three calls:

1. **Long-poll config** — `GET /policy?wait=30s` with an `If-None-Match` ETag. The
   CP holds the request open and returns **200 + new policy the instant it
   changes**, or **304** at the timeout; the worker re-polls immediately. Policy
   edits reach workers in ~one round-trip, not after a fixed interval.
   The same response carries `registeredAgents` (each registered agent's id, status and key
   thumbprints), from which the worker takes the status of the agent it is bound to
   ([the kill switch](#the-kill-switch)).
2. **Heartbeat** — `POST /control/heartbeat` (~every 10s) so the CP lists the
   worker as online even when idle, and knows its current policy version and the
   capabilities it advertises (`caps`, e.g. `blocklist/v1`), so the console can flag
   workers that would silently ignore newer policy fields. It may also carry
   `agentID` (the registered agent the worker serves; dropped unless it is a valid
   agent id) and `identityMode` (`off|attribute|challenge|require`; dropped otherwise),
   which the console's **Agents** tab joins with the agent registry to show each
   agent's bound workers and to warn about unregistered or unserved agents. The tab
   appears only on a control plane with a state dir.
3. **Analytics** — `POST /central/ingest` (worker → CP).

The dashboard shows only what the CP already has (pushed analytics + the
registry); it never reaches into a worker.

## Managed vs local-only

By default a worker with `controlPlane.endpoint` set is **CP-managed**: its
allow/deny policy comes **only** from the control plane. It boots **fail-closed
(denies all egress)** until its first successful pull, then enforces CP policy and
keeps the last-known-good across CP outages — it never falls back to a local
allowlist the operator didn't intend. (Secrets always stay local; "managed" is
about allow/deny policy only.)

Set `controlPlane.localOnly: true` (or run `warden run --local-only`) to ignore
the control plane and enforce the worker's **local** policy standalone — the
escape hatch for offline/debug. A managed worker needs no local `allowlist`; a
local-only/standalone worker still requires one.

## Pinning bundle keys (worker config)

A worker pins the public keys that may sign the policy bundles it accepts. Since
the Phase 2 release a CP-managed worker **requires** pins: with none pinned and
no explicit opt-out the config fails to load, naming `controlPlane.bundleKeys`
and `controlPlane.bundleKeysFile` and the opt-out; the worker never falls back to
unsigned policy on its own. The opt-out is `controlPlane.requireSignedBundles:
false` (a worker with that and no pins takes policy unverified and logs one WARN,
`bundle verification disabled (no controlPlane.bundleKeys, controlPlane.requireSignedBundles: false)`).
See [Upgrading to required signed bundles](#upgrading-to-required-signed-bundles).

With pins the worker sends `Accept: application/vnd.warden.bundle.v1+json` on every
policy pull and applies only a bundle that verifies (signature, seq, expiry,
issuer, credential hash). It never applies the unsigned wire: a legacy 200 is
rejected as `unsigned`. A rejected bundle changes nothing, so the worker keeps
enforcing its last-known-good policy (and a disabled agent stays disabled); its
ETag is sent as `If-None-Match` on the next long-poll so the bad bundle is not
downloaded again (except `future` and `expired`, which depend on the clock and
are fetched again). One WARN per distinct rejection names the reason, seq and
kid, never payload or credential values. A bundle that is signed correctly but
carries a policy the worker cannot enforce (for example an invalid
`registeredAgents` list) is rejected whole as `invalid_policy`. `bundleExpiry`
decides what happens when the held bundle passes `expiresAt` (plus skew) with no
valid replacement: `keep` (default) keeps enforcing it and logs a WARN, `deny`
denies all traffic until a valid bundle arrives. A control plane started with
`--bundles=require` (the default when its prerequisites are present) answers a
worker without pins `406 signed_bundle_required`; the worker logs a hint to pin
the bundle keys.

| Key | Default | Meaning |
|---|---|---|
| `controlPlane.bundleKeys` | none | List of public JWKs (OKP/Ed25519 or EC/P-256). |
| `controlPlane.bundleKeysFile` | none | JWKS JSON file `{"keys":[...]}`, merged with `bundleKeys`. |
| `controlPlane.requireSignedBundles` | `true` | A CP-managed worker (endpoint set, neither `controlPlane.localOnly` nor `--local-only`) with no keys pinned fails at startup. `false` is the explicit, temporary opt-out: the worker takes unsigned policy and logs a WARN at boot. Pins always verify, whatever this says. |
| `controlPlane.bundleIssuer` | none | When set, a bundle's `cpId` must equal it. |
| `controlPlane.bundleClockSkew` | `5m` | Tolerance on `issuedAt` and `expiresAt`, at most `1h`. |
| `controlPlane.bundleExpiry` | `keep` | `keep` enforces the last-known-good past expiry, `deny` blocks. |

Inline and file keys together are at most 16. Every pin must have no private
members and a `kid` equal to its RFC 7638 thumbprint (a kid mismatch error shows
the expected thumbprint), and a repeated kid is an error. List both the old and
the new key while the control plane rotates its bundle key. Errors name
`controlPlane.bundleKeys[i]` or `controlPlane.bundleKeysFile[i]` and never
include key material. `controlPlane.localOnly: true` ignores all of these keys
and logs one INFO line.

### Upgrading to required signed bundles

**Breaking change in the Phase 2 release.** Two defaults flip together:

| Side | Before | Now |
|---|---|---|
| Control plane `--bundles` | `off` | unset = `require` when `--state-dir`, `--policy-store=versioned` and `keys.enabled: true` are all present; otherwise the legacy unsigned policy and one startup WARN naming what is missing |
| Worker `controlPlane.requireSignedBundles` | `false` | `true`: a CP-managed worker with no `bundleKeys` or `bundleKeysFile` fails to start |

A worker never falls back to unsigned by itself: one that upgrades without pins
stops at startup with an error that names the keys to pin and the opt-out. The
control plane differs: with `--bundles` unset and a prerequisite missing it serves
the unsigned policy and logs one WARN naming the gap. A pinned worker rejects that
as `unsigned`, and an unpinned worker does not start without the opt-out.

**Do these in order, before you upgrade any binary.**

1. **Pin first.** The control plane needs the prerequisites (`--state-dir`,
   `--policy-store=versioned`, `keys.enabled: true`). Start it once so it creates
   its bundle key, with `--bundles=offer` set explicitly (offer serves the
   envelope to workers that ask for it and the unsigned policy to the rest, so no
   unpinned worker breaks), then export the public keys:

   ```sh
   warden control-plane keys export --purpose bundle --state-dir /var/lib/warden-cp \
     > bundle-keys.json
   ```

   Put the file on every worker and set `controlPlane.bundleKeysFile` to it (or
   inline `controlPlane.bundleKeys`). Pinning works on every release that has
   signed bundles, so pin the old binaries now; the fleet view shows each pinned
   worker's `bundleSeq`, `pinnedKids` and the `bundle/v1` capability. A worker too
   old to pin must be upgraded to a release that can before anything else.
2. **Upgrade the workers** (any order among themselves). A pinned worker sends
   the bundle `Accept` header, applies only bundles that verify and never the
   unsigned wire.
3. **Upgrade the control plane**, keeping `--bundles=offer` until the fleet view
   shows no worker without `bundle/v1`. Then remove the flag: the control plane
   resolves to `require` and answers an unpinned request `406 signed_bundle_required`.
   (`docker-compose.bundles.yml` is this path in compose: it exports the pins and
   starts each worker pinned.)

**Opting out, temporarily.** Both opt-outs are explicit and log a WARN (the
control plane's unset-flag fallback above logs one too):

- Control plane: `--bundles=off` serves the legacy unsigned policy and logs
  `--bundles=off serves the legacy unsigned policy; this is a temporary opt-out`
  (`--bundles=offer` also logs a WARN: it serves unsigned policy to unpinned workers).
- Worker: `controlPlane.requireSignedBundles: false` (the WARN above). Pins, when
  present, still verify. `warden run --local-only` ignores the control plane and
  needs no pins; the check runs only for a worker that is CP-managed.

**What a worker does when the control plane serves no signed envelope.** It fails
closed, not open:

- A pinned worker rejects an unsigned 200 as `unsigned` (a control plane with
  `--bundles=off`, or one without the prerequisites, serves exactly that), counts
  `warden_bundle_rejected_total{reason="unsigned"}` and keeps enforcing its
  last-known-good policy. Booted with nothing applied it denies all traffic, as
  it does before its first pull. With `controlPlane.stateDir` it may start from
  the [last-known-good cache](#last-known-good-bundle-cache-opt-in) if that verifies.
- `503 signed_bundle_unavailable` (the control plane is degraded and has no
  envelope) is a failed pull: the same last-known-good, no fallback.
- `406 signed_bundle_required` to a worker without pins (a control plane on
  `require`, a worker on the opt-out) is a failed pull with a hint to pin.
- An upgraded worker with no pins and no opt-out does not start.

**Mixed-version fleets.** Mixed is safe only through `--bundles=offer`. Against a
control plane on `require`, a worker without pins keeps its in-memory policy until
it restarts, then denies all traffic. Against an old control plane (`--bundles`
off), a pinned worker rejects its unsigned policy; keep the old workers on the
opt-out until the control plane is upgraded and signing. The control plane serves
a `bundle/v1` worker the envelope and an older worker the unsigned policy in
`offer`; "N connected workers do not verify signed bundles" in the fleet view
counts the rest.

**Rollback.** Roll back one side at a time and keep the two consistent:

- Control plane to the previous release, or to unsigned: start it with
  `--bundles=offer` (pinned workers keep their verified envelopes, unpinned ones
  keep the unsigned policy). Use `--bundles=off` only when no worker is pinned,
  because a pinned worker rejects every unsigned policy and holds its last-known-good.
- Worker to the previous release: its config still loads (the key is the same
  boolean), and an old binary with pins still verifies. A worker that must run
  without pins needs `controlPlane.requireSignedBundles: false` on the new
  binary, or no pins on the old one.
- A binary rollback moves no seq. A worker holding the
  [last-known-good cache](#last-known-good-bundle-cache-opt-in) refuses a lower
  seq until the cached bundle expires (about 24h by default), so after restoring
  control-plane state from a backup set `--bundle-seq-floor` above the highest seq
  any worker reports ([runbook](runbooks/key-rotation.md)).

### Last-known-good bundle cache (opt-in)

By default a CP-managed worker that boots while the control plane is down stays
fail-closed (deny all) until its first successful pull. A pinned worker can
instead keep its last verified bundle on disk and enforce it at boot.

The cache is off unless `controlPlane.stateDir` is set **and** bundle keys are
pinned. `stateDir` is the worker's one local state directory (an absolute path,
created `0700`); each use gets a subdirectory: `cert/` for the worker
certificate and `bundle/` for this cache. There is no separate cache directory
key.

| Key | Default | Meaning |
|---|---|---|
| `controlPlane.stateDir` | none | Absolute path of the worker state directory. With pinned keys it turns the cache on. |
| `controlPlane.bundleCacheMaxAge` | `24h` | A cached bundle is used only if it was issued at most this long ago. `0` disables the cache (nothing is written or read). |

What is written. After every verified bundle, including a re-signed one with the
same content (which moves `issuedAt`), the worker writes
`<stateDir>/bundle/bundle.json`: the verified payload and signatures,
re-marshalled in canonical form, with no `credentials` sidecar and no other
envelope member. The write is atomic (temp file in the
same directory, fsync, rename, directory fsync); the file is `0600` and the
directory `0700`. A failed write logs one ERROR (until a write succeeds again)
and never changes the policy being enforced. The file holds policy and
signatures only: never `secretAccessKey` and never any other secret, and its
content is never logged.

When it is read. Only when the boot pull fails (control plane down, or serving a
bundle the worker rejects). The cached envelope is verified again exactly like a
live one: against the current pins, the issuer, `issuedAt` and `expiresAt` (with
the skew), and additionally `issuedAt` must be within `bundleCacheMaxAge`. The
only relaxation is that the missing credentials sidecar is allowed. A cache that
is missing, corrupt, tampered with, signed by a key that is no longer pinned,
expired or too old is refused: the worker logs one WARN, `starting FAIL-CLOSED`,
with the reason in `bundleCache`, and denies all traffic as it does without a
cache. A cache that passes seeds the applied bundle state, so a control plane
that later serves an older seq is rejected as a rollback, and an equal seq with
different content as equivocation. The worker logs one WARN that it is enforcing
the cached bundle, and the long-poll then takes over as usual.

Credentials. The sidecar (the AWS access key pair for the `aws` secret backend)
is deliberately not cached. A worker running from the cache therefore has the
`aws` selector (backend, region, name prefix) from the signed policy but no
explicit key pair, so the secret backend resolves credentials from the worker's
own environment (`AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY`) or the instance
IAM role. If neither exists the worker still starts and enforces the cached
allow/deny policy: it logs one ERROR, and every secret fetch fails (so requests
that need a secret are not served) until a restart with the control plane
reachable, when the credentials arrive again.

Rollback floor. A control plane that is up at boot is not trusted blindly either:
when the cache verifies (pins, issuer, not expired), its seq is the floor of the
boot pull. A bundle with a lower seq is rejected as a rollback, and the same seq
with different content as equivocation; the pull then fails and the worker
enforces the cached bundle. The control plane serving the cached bundle itself is
applied normally (credentials included). This goes beyond the "cache is read only
when the boot pull fails" wording of the original ticket and is bounded: a control
plane restored from an old backup that serves a lower seq is refused only until
the cached bundle expires (about 24h by default; the bundle lifetime, not
`bundleCacheMaxAge`), after which the cache stops being a floor and the worker
accepts the control plane's bundles again. Use `--bundle-seq-floor` on the control
plane to recover sooner.

Key rotation. The cache is verified at boot under the pins the worker holds
then, like any bundle, and it keeps every signature of the envelope it saved. A
worker restarted mid-rotation therefore verifies a dual-signed cache under either
the old or the new pin. A cache only the old key signed is refused once the old
pin is dropped, which is why the runbook keeps the old pin until the overlap has
passed and a new-key bundle has been applied everywhere; the worker then falls
back to the control plane, and fails closed if that is down too.

File safety. `stateDir` and `bundle/` must be real directories (a symlink is
refused), owned by the worker user and not writable by group or others; a worse
directory disables the cache with one ERROR. The cache file is opened without
following symlinks and without blocking, must be a regular file, and must not be
accessible by group or others (mode `0600`), otherwise it is refused and the
worker boots fail-closed. The cache can only be loaded at boot, before the first
long-poll. The parent of `stateDir` is not checked: put `stateDir` under a
root-owned path such as `/var/lib/warden`. A `stateDir` that was pre-created
under a group-writable umask (for example 002) is refused, which disables the
cache with one ERROR.

Operations. The state directory must not be readable or writable by the agent it
guards: a writable cache cannot make the worker enforce a forged policy
(signatures are checked), but it can be deleted or replaced by an older valid
bundle within `bundleCacheMaxAge`, which is why the max age exists. Keep it short
if a restart must not bring back an older block list.

### Bundle state in metrics and the fleet view

A pinned worker reports its bundle state three ways.

- Metrics (when observability metrics are on): `warden_bundle_rejected_total{reason}`
  (`reason` is one of the bundle rejection reasons or `invalid_policy`), and the
  gauges `warden_bundle_seq` (the bundle in force; a rejected bundle leaves it
  unchanged), `warden_bundle_age_seconds` and `warden_bundle_stale` (1 once the
  bundle in force is past its expiry). Kids are never labels. The gauges refresh
  every 10 seconds.
- Heartbeat: the optional fields `bundleSeq`, `bundleKid`, `bundleIssuedAt`,
  `pinnedKids` (at most 8), `bundleStale`, `lastRejectReason` and `lastRejectAt`,
  and the capability `bundle/v1`. A worker without pins sends none of them, and a
  control plane that does not know them ignores them.
- Fleet view: the console shows each worker's bundle seq, a rejection badge with the
  reason, and "N connected workers do not verify signed bundles" while the control
  plane serves bundles. For a worker that advertises `bundle/v1`, `behind` means its
  seq is below the control plane's newest signed seq. A worker that reports a seq
  above it is flagged `bundleSeqAhead` and logged once as an ERROR: the control
  plane was probably restored to older state. The control plane logs
  `worker bundle rejected` (proxy id, `applied_seq` — the bundle the worker
  still enforces, not the rejected one — and reason) once per change of reason.

## Run it

```sh
# 1. Generate the bake-once proxy CA (the control plane mints its cert from it).
OUT_DIR=deploy/compose/certs ./scripts/gen-certs.sh
#    The key is mode 0600 for you; the container's warden user (uid 100) must read it.
#    Dev only: chmod 644 deploy/compose/certs/proxy-ca.key  (or chown 100:101 it with sudo).

# 2. Bring up the control plane + two workers + two synthetic agents. The compose
#    defaults are public dev placeholders (deploy/compose/.env.example); for
#    anything but a laptop, set your own values first (see below).
docker compose -f deploy/compose/docker-compose.control-plane.yml up
```

The recipe runs on [worker certificates](#worker-ca-workerca) and the control plane is strict
(`--require-worker-certs`; its startup log shows `auth_mode=strict-certs` and `worker_ca=enabled
key_source=file`, with the development-only warning). A one-shot `cp-bootstrap` service creates the
worker CA with `warden control-plane ca init --key-source file` into its own `cp-ca` volume (never the
control plane's state volume; skipped when the files exist, and `root.key` is deleted at once), and
registers one enrollment token per worker with `warden control-plane enroll-token create --from-env`
on the state volume (`cp-data`), before the control plane and the workers start. Each worker enrolls
once with its token, keeps the 24h certificate renewed and persists it under `controlPlane.stateDir`
(`/data/cp` on its own volume), so while that certificate is valid a restart or a second `up` neither
re-enrolls nor creates a token row. The workers share `configs/config.worker.yaml`: `controlPlane.enrollment.tokenEnv` names
`WARDEN_WORKER_ENROLL_TOKEN`, which each service fills from its own `WARDEN_WORKER_1_ENROLL` or
`WARDEN_WORKER_2_ENROLL`, and there is no `tokenEnv` and no `WARDEN_CP_TOKEN`. The first run builds
the image from the repo (the published image predates the worker CA commands). A `wwt_` bearer
without a client certificate gets `401`. The e2e stack and the other recipes still run on per-worker
`wwt_` tokens.

**Recovery.** A certificate lives 24h and is renewed at about 12h, an enrollment token is good for one\
use and one hour, and the CA for one year. A stack left stopped past a certificate's expiry, a first `up`\
retried after the token's hour, or a CA past its year leaves workers unable to enroll, and `cp-bootstrap`\
never revives a used or expired token or re-creates an existing CA. Two ways out:

```sh
# 1. Reset everything (dev data is disposable): new CA, new tokens, new certificates.
docker compose -f deploy/compose/docker-compose.control-plane.yml down -v
docker compose -f deploy/compose/docker-compose.control-plane.yml up -d

# 2. Keep the state: mint a new token for the worker, then clear its old certificate.
docker compose -f deploy/compose/docker-compose.control-plane.yml exec control-plane \
  warden control-plane enroll-token create --name w1-2 --worker-id worker-1 \
  --from-env WARDEN_WORKER_1_ENROLL --state-dir /data
```

For the second way, export a fresh `wet_` value as `WARDEN_WORKER_1_ENROLL` in your shell first (the
`exec` runs in the container, so pass it with `exec -e WARDEN_WORKER_1_ENROLL`), then remove the worker's old
pair, `/data/cp/cert/worker-cert.pem` and `worker-key.pem` in its `worker1-data` volume, and run
`up -d` so the worker restarts with the new value. An expired CA needs way 1.

To use your own values, generate one enrollment token per worker and export it (or put it in a
git-ignored `deploy/compose/.env`) before `up`:

```sh
echo wet_$(head -c32 /dev/urandom | base32 | tr -d = | tr A-Z a-z | head -c52)   # one per worker
export WARDEN_WORKER_1_ENROLL=wet_...  WARDEN_WORKER_2_ENROLL=wet_...  WARDEN_CP_ADMIN_TOKEN=...
```

Never commit a real value. [`deploy/compose/.env.example`](../deploy/compose/.env.example) lists the
variables with obviously fake dev placeholders. An enrollment token is good for one enrollment and,
by default, for one hour after `cp-bootstrap` registers it: a worker whose volume is lost later needs
a new token ([re-enroll a worker](runbooks/worker-certs.md#re-enroll-a-worker)). Dashboard writes
(policy edits) need `Authorization: Bearer $WARDEN_CP_ADMIN_TOKEN`; a worker credential never opens them.

- Fleet dashboard: **https://localhost:7070/dashboard/** (cert signed by the
  proxy CA — trust it in your browser, or `curl --cacert deploy/compose/certs/proxy-ca.crt`).
  A **worker selector** appears top-left: view the whole fleet or slice to one
  worker. The **policy panel is live** — it reflects the current served policy.
- Per-worker dashboards: http://localhost:9091/dashboard/ and http://localhost:9092/dashboard/.

Edit [`configs/config.control-plane.yaml`](../configs/config.control-plane.yaml)
(add/remove an allowed domain) and within one poll interval both workers enforce
the change — no restart.

## Standalone (no Docker)

```sh
# Control plane (HTTPS, minted from the proxy CA):
warden control-plane --config configs/config.control-plane.yaml \
  --listen 0.0.0.0:7070 --legacy-token-env WARDEN_CP_TOKEN \
  --admin-token-env WARDEN_CP_ADMIN_TOKEN \
  --ca-cert certs/proxy-ca.crt --ca-key certs/proxy-ca.key --tls-host control-plane

# Worker pointed at it (configs/config.worker.yaml sets controlPlane + central):
WARDEN_PROXY_ID=worker-1 warden run --config configs/config.worker.yaml ...
```

Omit `--ca-cert`/`--ca-key` to serve plain HTTP for local poking, but a real
worker requires HTTPS for the policy pull.

## What the control-plane dashboard does

- **Edit policy** — add/remove allow and deny rules from the dashboard and Save.
  The edit is validated (an empty allowlist is rejected — default-deny is
  preserved) and written back to the served policy file, so every worker pulls it
  on its next poll. The editor only appears on the control plane; worker
  dashboards show policy read-only and expose no write path.

  > **Writable served config required.** Saving an edit writes a temp file next
  > to the served config and atomic-renames it into place, so the served config
  > must live on a writable, container-user-owned location. Pass
  > `--state-dir=<writable dir>` (the compose uses `/data`): the control plane
  > seeds it once from `--config` and then serves+edits that writable copy, so
  > edits persist across restarts. Without `--state-dir` the control plane edits
  > `--config` in place — fine for a writable file, but with a read-only
  > single-file `--config` mount (see [Standalone](#standalone-no-docker), the
  > `:ro` mount) the dashboard surfaces a `permission denied` error and editing
  > is effectively disabled. The control plane logs a clear warning at startup
  > when its served-config directory is not writable.
  >
  > **One control plane per state dir.** With `--state-dir` the control plane holds
  > an exclusive lock on `<state-dir>/warden-cp.lock` (mode 0600, holds the PID for
  > operators) for as long as it runs; a second control plane on the same dir fails
  > with `state dir ... is in use by another control plane`. A crash drops the lock
  > automatically, so there is no stale lock to clear. Unix only.
- **Connected workers** — a live list of every worker the control plane has heard
  from (via policy pulls and analytics ingest): online/offline status, last-seen,
  last policy pull, and events forwarded. Hidden on a single-node dashboard.
- **Per-worker slicing** — events are tagged with their originating worker, so the
  dashboard shows a per-worker breakdown and lets you filter the whole view to one
  worker.
- **MCP per worker** — each worker forwards its MCP inventory + observed
  request/response schema (value-free: paths · types · the specific detector that
  fired — e.g. `github_token · HIGH`, `email · MEDIUM`) over the ingest channel,
  so the control-plane MCP panel shows it per worker (follows the worker
  selector). Requires `mcp.enabled` on the worker.
- **Debug a finding** — expand a flagged field to see the exact detector +
  severity (not just the coarse `credential_leak`/`pii` class). Set
  `mcp.scan.evidence: true` on a worker to also keep a **masked** sample
  (`•••• + last-4 (len N)`, never the raw value) so you can tell a real leak from
  a false positive. From a flagged tool you can **Deny it fleet-wide** in one
  click — that writes `settings.mcp.tools.deny` via the same validated settings
  writer, so every worker blocks the tool on its next poll.
- **Live policy** — the policy panel reflects the policy currently being served
  (control plane) or enforced (worker, including hot-reloads), not a startup snapshot.
- **Alert integrations** — configure outbound alert sinks (webhook today) from the
  dashboard. Secrets are entered as `${ENV}` references only (raw values are
  rejected) and resolved from the control plane's environment at start.

### Verifying webhook signatures

If a webhook integration has a **Signing secret** configured, every delivery is
signed Slack/Stripe-style so your receiver can authenticate the payload and
reject replays:

- `X-Warden-Timestamp: <unix seconds>` — when the request was sent.
- `X-Warden-Signature: v1=<hex>` — where `<hex>` is
  `HMAC-SHA256(secret, "<timestamp>.<raw request body>")`.

To verify: read the raw body bytes **before** JSON-parsing, recompute
`hex(hmac_sha256(secret, timestamp + "." + body))`, compare against the value
after `v1=` with a constant-time comparison, and reject requests whose
timestamp is older than your replay window (e.g. 5 minutes). Without a
configured secret the headers are absent and deliveries are unsigned.

### Dashboard writes need the control-plane token

This is the `console.auth: none` mode (the default). Dashboard reads are open;
every state-changing call under `/dashboard/api/` (`PUT`, `POST`, `PATCH`,
`DELETE`: policy, settings, integrations, detection, LLM providers, the secret
store, and the query and audit-verify `POST`s) is gated by the control-plane
admin bearer, `Authorization: Bearer <control-plane admin token>`, checked in
constant time and fail closed. `/central/secrets` (GET, POST and
`DELETE /central/secrets/{key}`) takes the same bearer in this mode. In
`console.auth: oidc` none of this applies: sessions and CSRF replace the bearer
on every human route (see [Migrating from none to oidc](#migrating-from-none-to-oidc)).

- **The admin token.** Start the control plane with `--admin-token-env <ENV>`
  (for example `--admin-token-env WARDEN_CP_ADMIN_TOKEN`) naming the env var that
  holds its own admin bearer. It is separate from the `--legacy-token-env` token workers
  present: once it is set, the worker token gets `401` on dashboard writes and on
  `/central/secrets`, and the admin token gets `401` on the worker routes
  (`/policy`, `/control/heartbeat`, `/central/ingest`). Use different values; the
  control plane warns at startup when the two are equal. Scripts that write with
  `curl -H "Authorization: Bearer ..."` must send the admin token once it is set.
  Giving the control plane its own admin token means retiring the shared worker
  token (per-worker tokens) never disables dashboard writes.
- **Fallback.** Without `--admin-token-env`, the admin bearer is the shared
  `--legacy-token-env` token, exactly as before, and startup logs one warning:
  `dashboard writes use the shared worker token; set --admin-token-env`. With no
  token of either kind, `/central/secrets` keeps the development pass-through of
  the worker routes, and dashboard writes are refused (below).
- **Visible.** At startup the control plane logs one warning,
  `console.auth=none: dashboard reads are unauthenticated; writes need the admin bearer`,
  `GET /dashboard/api/setup` returns `"authMode":"none"`, and the dashboard shows a
  persistent "Open console" banner. Start the control plane with
  `--require-console-auth` to make none mode a startup error instead.

- **Fail closed.** A control plane started with no admin bearer (neither
  `--admin-token-env` nor `--legacy-token-env`, or their variables empty) refuses every
  dashboard write with `403` and a message (`dashboard writes are disabled`) that
  names `--admin-token-env`. There is no open mode for dashboard writes. A
  whitespace-only token counts as not configured. When `--admin-token-env` names
  an empty variable the control plane logs
  `control-plane: admin-token-env set but empty; dashboard writes will be refused`
  and does not fall back to the worker token: dashboard writes get `403` and
  `/central/secrets` gets `401`. No token value is ever logged. The worker-facing endpoints
  (`/central/ingest`, `/control/heartbeat`) keep the existing development
  pass-through when no token is set; the loopback publish of `:7070` in the demo
  compose files is what bounds that.
- **Reads stay open.** `GET` routes (traffic, analytics, policy view, workers, …)
  need no token. Restrict `:7070` to operators regardless: the demo compose files
  publish it, and each worker's `:9090` admin/dashboard port, on `127.0.0.1` only.
- **The UI asks once.** A change goes out without a token first; a `401` prompts for the token and retries once. It is kept in `sessionStorage` (this tab only; never `localStorage` or a
  cookie) and sent as the bearer header. A `401` clears it.
  Because the credential is a header the page adds itself, a cross-site form or
  request cannot make the browser send it: writes are CSRF-safe.
- **Audit.** A refused write logs `control plane dashboard write refused` with the
  method, path, remote address and reason, never the token. A successful write
  logs as before.

```sh
curl --cacert proxy-ca.crt -X PUT https://localhost:7070/dashboard/api/policy \
  -H "Authorization: Bearer $WARDEN_CP_ADMIN_TOKEN" -H 'Content-Type: application/json' \
  -d '{"allowlist":[{"domain":"api.openai.com"}],"denylist":[]}'

# Secret writes take the same admin bearer:
curl --cacert proxy-ca.crt -X POST https://localhost:7070/central/secrets \
  -H "Authorization: Bearer $WARDEN_CP_ADMIN_TOKEN" -H 'Content-Type: application/json' \
  -d '{"key":"openai","value":"..."}'
```

Without `--admin-token-env` (the fallback), use `$WARDEN_CP_TOKEN` in these
examples instead.

A worker's own admin dashboard (its local `:9090`) is a separate listener with its
own token, not this one: see [Worker admin token](#worker-admin-token).

## Console sign-in config

The control plane reads an optional `console:` block from the operator-owned
`--config` file (never the `--state-dir` copy, which is seeded once and rewritten by
the dashboard, so a different block there is ignored with a warning). It is
control-plane-local: it never reaches a worker or the settings wire, and changing it
needs a restart. It holds the *name* of the client-secret env var, never the secret.

| Key | Default | Notes |
|---|---|---|
| `auth` | `none` | `none` keeps today's behaviour; `oidc` enables SSO. Any other value is a startup error. |
| `oidc.issuer`, `oidc.clientSecretEnv`, `oidc.redirectURL` | required for `oidc` | The issuer must be https unless `oidc.internalIssuerURL` is set (the dev profile); `redirectURL` is absolute, ends in `/auth/callback` and is https unless its host is loopback. |
| `oidc.clientID` | `warden-console` | The reference Dex client. |
| `oidc.scopes` | `openid email profile groups` | Must include `openid`. |
| `oidc.internalIssuerURL` | none | Origin the control-plane container uses to reach the IdP, for example `http://dex:5556`. Origin only; there is no insecure-issuer key. |
| `roles.admin`, `roles.editor`, `roles.viewer` | none | IdP group names, matched exactly and case-sensitively; the highest matching role wins. `roles.admin` needs at least one group. |
| `session.idle`, `session.absolute` | `1h`, `12h` | `0 < idle <= absolute <= 168h`. |
| `adminAudit.enabled` | `false` | Turns on the signed admin audit log; needs `--state-dir`. See [Admin audit log](#admin-audit-log). |
| `trustedProxies` | none | CIDRs of reverse proxies in front of the control plane. Only a peer inside one may set the client address the admin audit log records, through `X-Forwarded-For`. A bare address or anything that is not a CIDR is a startup error. |
| `approvals.enabled` | `false` | Change approvals (W-P2-APPR-01). Every versioned write path is gated (see "Which writes are gated"). Off, no table, migration or goroutine exists and `/policy` is unchanged. When on it needs `console.auth: oidc`, `--policy-store=versioned`, `--state-dir` and `adminAudit.enabled: true`; startup names the first one missing. Read from `--config` only and never sent to workers. |
| `approvals.minApprovals` | `1` | Distinct approvers a held change needs, `1..3`. |
| `approvals.allowSelfApproveNarrowing` | `true` | A narrowing change applies at submit with no second person. |
| `approvals.allowEmergencyApply` | `false` | Allows the audited break-glass apply. |
| `approvals.replayWindow` | `168h` | How far back a replay reads fleet events, `1h..720h`. |
| `approvals.replayMaxEvents`, `approvals.replayTimeout`, `approvals.replayMaxAge` | `100000`, `60s`, `24h` | Replay event cap (`1..100000`), run timeout and the age a replay may have and still back an approval. |
| `approvals.draftTTL`, `approvals.maxOpenDrafts` | `168h`, `200` | An open draft expires after the TTL; creating a draft past the cap is refused. Out-of-range values are startup errors even while disabled. |
| `apiKeys.enabled` | `false` | Turns on scoped `wak_` API keys on `/dashboard/api/*`; needs `auth: oidc` and `--state-dir`. See [API keys](#api-keys-consoleapikeys). |
| `apiKeys.defaultTTL`, `apiKeys.maxTTL` | `2160h`, `8760h` | Default and maximum key lifetime; `maxTTL` is also a hard ceiling and `defaultTTL <= maxTTL`. |
| `apiKeys.maxPerOwner`, `apiKeys.ratePerKey` | `25`, `10` | Active keys one owner may hold; requests per second one key may make (burst 2x). |

Running the identity provider itself (Dex clients, connectors, the split-horizon issuer, failure modes and the production checklist) is covered in [Running Dex as Warden's identity provider](identity-dex.md).

In `oidc` mode the control plane also needs a non-empty value in the client-secret env
var and `--state-dir`; without either it refuses to start. See
`configs/config.control-plane.yaml` for commented examples.

In `oidc` mode every human route needs a session: each `/dashboard/*` route needs at
least the viewer role, writes need the CSRF header, and `/central/secrets` (GET, POST
and `DELETE /central/secrets/{key}`) needs an admin session plus CSRF. An
`Authorization` header is ignored on those routes, so neither the shared
`--legacy-token-env` token, the `--admin-token-env` token nor any other bearer opens them (401 without a session, 403 for a
role below admin). The worker routes (`/policy`, `/control/heartbeat`,
`/central/ingest`) keep the shared bearer in both modes.

### Admin audit log

`console.adminAudit.enabled: true` turns on the admin audit log: a hash-chained,
Ed25519-signed table in `<state-dir>/warden-cp.db`. It is off by default. Off, the
control plane creates no key file, no HMAC key file and no audit rows, and behaves
exactly as before. On without `--state-dir` it refuses to start
(`control-plane: console.adminAudit.enabled needs --state-dir`).

The first enabled start creates the signing key at `--admin-audit-key-file` (default
`<state-dir>/cp-audit.key`, PKCS#8, mode 0600) and the actor HMAC key
`cp-audit-hmac.key` beside it, writes the chain's genesis entry and logs one
`admin audit enabled` line with `key_id` and the base64 public key (never the private
key or the HMAC key). Put the key on a separate secret mount with
`--admin-audit-key-file=/secrets/cp-audit.key`; the HMAC key then lives in
`/secrets` too.

Every later start checks the keys before serving and fails closed when the chain has
rows and:

- the key file (or the HMAC key file beside it) is missing. A missing key is never
  replaced silently; restore it from backup.
- the key's `key_id` is not the chain head's `key_id` — except right after a signed
  rotation: when the head is an `audit.key_rotated` entry, the key it hands the
  chain to is accepted, and a retired key copied back is refused with the expected
  `key_id` named. The error names the expected `key_id` and `--admin-audit-key-file`.
- the HMAC key does not match the one the chain was started with.

Turning the feature off again keeps the rows and the tables; the control plane always
registers the admin audit migration, so the state database never trips the
downgrade guard.

**Key rotation.** `warden control-plane admin-audit rotate-key --state-dir <dir>`
(W-P2-KEYS-06) is the supported way to change the signing key, run offline with the
control plane stopped (it takes the state-dir lock and exits 1 with `control plane
is running` otherwise). It generates a new Ed25519 key, appends one
`audit.key_rotated` entry signed by the old key — linked to the head and carrying
`old_key_id`, `new_key_id` and the new public key — then replaces the key file and
keeps the old key beside it as `<key>.<old_key_id>.key.retired` (mode 0600). The
HMAC key does not change. The next start accepts the new key because the chain
names it; verification learns keys from the chain itself, so a `key_id` change is
legal only as the take-up of a `key_rotated` entry, `admin-audit verify` and
`admin-audit export` list every key of the rotation history in their `keys` record,
and `GET /dashboard/api/admin-audit/pubkey` serves the same list. Restores accept a
backup whose manifest fingerprint names any key in that history. A run interrupted
between the entry and the file swap is completed by re-running `rotate-key`. The
step-by-step procedure is
[docs/runbooks/admin-audit-key.md](runbooks/admin-audit-key.md).

**Manual key change (new segment).** `--admin-audit-new-segment` is recovery for a
lost key, when no one can sign a handover entry: stop the control plane, check and
archive the chain with `admin-audit verify` and `admin-audit export`, put the new
key at `--admin-audit-key-file` with the same `cp-audit-hmac.key` beside it, and
start once with `--admin-audit-new-segment=<new key_id>`. The control plane logs a
WARN naming `admin-audit rotate-key` as the supported path, appends one
`audit.segment_start` entry signed by the new key, linked to the old head and naming
the previous `key_id`; every later row carries the new `key_id`, and verification
reads each segment's public key from the chain. The flag must equal the loaded key's
`key_id` (anything else stops startup) and is a no-op once the head is on that key,
so leaving it set can never rotate twice. The flag without
`console.adminAudit.enabled` is a startup error.

**Startup verification.** After the key check, every enabled start verifies the
newest 1000 rows and the head signature. A failure logs
`admin audit chain verification failed` at ERROR (with `first_bad_seq` and `reason`)
and publishes an `admin_audit_verify_failed` Finding (severity critical) to the alert
pipeline; a chain that cannot be read at all raises the same Finding with reason
`verify_error`. The control plane still starts and serves `/policy`.

**Offline verify and export.** Two subcommands check the chain without a running
control plane, for example after a restore or when the control plane is down. Both
open `<state-dir>/warden-cp.db` read-only (the file's bytes and mtime stay unchanged),
read public keys from the chain, never load the signing key and write no audit row.

```sh
warden control-plane admin-audit verify --state-dir /data [--from-seq N] [--anchor seq:hash]
warden control-plane admin-audit export --state-dir /data --out audit.jsonl [--include-identity]
```

- `admin-audit verify` prints `{ok, checked, firstBadSeq, reason, headSeq, headHash,
  lastVerifiedSeq}` (hashes in hex) and exits 0 when the chain verifies, 1 when it does
  not (`firstBadSeq` is the first bad entry) and 2 on a usage or I/O error. `--anchor`
  takes an earlier `headSeq:headHash` and fails when the newest rows were removed.
- `admin-audit export` writes JSONL to a new file (mode 0600, never overwriting): one
  `keys` record with every `key_id`, its public key and first seq, then every entry in
  seq order. The side-table sub and email are left out unless `--include-identity` is
  set. `adminaudit.VerifyExport` verifies the file with no database.
- A state dir migrated by a newer Warden still opens: the read-only open tolerates
  migrations of other features it does not know, and refuses only an unknown
  `adminaudit/` migration (a chain layout this binary cannot read).

**What is recorded.** With the log on, every admin change made through the control
plane writes one row: dashboard policy, settings, detection, integrations and
llmproviders writes, `/dashboard/api/secretstore` POST and DELETE, `/central/secrets`
POST, `DELETE /central/secrets/{key}` and the admin session revoke
(`DELETE /dashboard/api/sessions`). Which routes count comes from the authz route
table (`Audited`), not from the HTTP method, so worker heartbeats, ingest, `/policy`
and the read-only POSTs (`/dashboard/api/query`, `query/generate`, `audit/verify`,
`admin-audit/verify`) never write a row. Each row carries:

- the actor: the session's subject, role and `auth_method` (`oidc` or `breakglass`),
  or, in `console.auth: none`, actor `cp-admin-token` with role `admin` and
  `auth_method` `bearer` for a write that presented the `--admin-token-env` bearer.
  A request with neither a session nor that bearer writes no row (it is counted and
  logged as `admin_audit_unauthenticated`, at most once a minute per client address).
  The one exception is a development control plane with no token configured at all,
  where `/central/secrets` accepts anonymous writes: a successful anonymous change is
  recorded with `auth_method` `none`; a failed or refused one still writes no row.
- the outcome: `ok` (2xx/3xx), `denied` (401/403, including a CSRF refusal, for an
  authenticated actor), `rejected` (other 4xx) or `error` (5xx), and the HTTP status.
- `before_hash` and `after_hash`: HMAC-SHA256 of the target's state with the
  CP-local HMAC key, so low-entropy config cannot be guessed from a hash. A denied
  write has equal hashes. Secret stores keep their state outside Warden, so secrets
  rows have empty hashes and name the key (`target_ref` `secret:<key>`, `op` put or
  delete); a policy write names the version written (`policy@<etag>`). No secret
  value, bearer or body is ever in a row.
- `request_id` (a valid incoming `X-Request-Id` of up to 64 `[A-Za-z0-9-]`
  characters, or a new one; echoed in the response) and `client_ip` (the peer
  address, or the left-most valid `X-Forwarded-For` address when the peer is in
  `console.trustedProxies`).

Audited changes run one at a time behind a control-plane-wide lock, so the hashes
describe exactly that change; a change that waits more than 30 s answers 503
`admin_audit_busy`. If a row cannot be appended after a change succeeded, the entry
is logged at ERROR with `persist_failed=true`, an `admin_audit_degraded` alert is
raised, and further audited changes answer 503 `{"error":"admin_audit_unavailable"}`
before they run, until the database accepts writes again. Reads, `/policy`, ingest
and heartbeats never depend on the audit log.

**Sign-ins and sign-outs.** In `oidc` mode the login and logout handlers record
their own rows (the middleware never wraps `/auth/*`), all with target `session`,
`auth_method` `oidc` (`breakglass` for the logout of a break-glass session), a `request_id` (echoed as `X-Request-Id`) and `client_ip`:

| Action | When | Actor | Outcome | Details |
|---|---|---|---|---|
| `auth.login` | `GET /auth/callback` created a session | the verified ID token's `sub` and `email`, role from `console.roles` | `ok` (status 302) | `{role}` |
| `auth.login_failed` | `GET /auth/callback` failed after its pending `state` was consumed | the verified token's subject when there is one (`no_role`), otherwise `anonymous` | `denied` or `error` (status 302) | `{reason}` |
| `auth.blocked_login` | `GET /auth/callback` refused a verified principal who is on the user block list | the verified token's `sub` and `email` | `denied` (status 403) | `{reason: user_blocked}` |
| `auth.blocked_session` | the session middleware refused a request from a blocked principal (at most one row a minute per principal) | the session's `sub` and `email` | `denied` (status 403) | `{reason: user_blocked}` |
| `auth.logout` | `POST /auth/logout` ended a live session | the session's user, captured before the row is deleted | `ok` (status 204) | none |
| `auth.breakglass` | `POST /auth/breakglass` (only with `console.breakGlass.enabled`) | `breakglass:<configured username>` on a username match, `breakglass:unknown` otherwise; `auth_method` `breakglass` | `ok` (200), `denied` (401), `error` (503); a rate-limited request adds at most one `denied` row (`{reason: rate_limited}`) per address per 15 minutes | none |

`target_ref` of `auth.login` and `auth.logout` is the first 8 hex characters of the
session's id hash (the `console_login`/`console logout` log lines use the same value),
so a sign-in and its sign-out can be matched. `details.reason` is a closed set:

| `reason` | Outcome | Cause (`login_error` code) |
|---|---|---|
| `no_role` | `denied` | the verified user matches no `console.roles` group (`no_role`) |
| `bad_token` | `denied` | the ID token failed verification or its nonce did not match (`token_invalid`, `nonce_mismatch`) |
| `state_invalid` | `denied` | the state was valid but the browser-binding login cookie was missing or wrong (`state_invalid`) |
| `idp_error` | `error` | the IdP answered with an error, or its keys could not be fetched (`idp_error`, `idp_unavailable`) |
| `exchange_failed` | `error` | no code, the token exchange failed, or the session could not be stored (`exchange_failed`) |

A principal on the user block list is refused at the callback with `403 {"error":"user_blocked"}`
and no session cookie, recorded as `auth.blocked_login` (it shares the 20-a-minute per-address
cap with `auth.login_failed`). While no block list has loaded (the first read of the state
database failed) `/auth/login` and the callback answer `503 {"error":"block_list_unavailable"}`
and a callback that got that far is recorded as `auth.login_failed` with reason
`block_list_unavailable`; `/policy` is not affected by the console check. The session
middleware also answers `403 {"error":"user_blocked"}` to a live session whose principal is
blocked, from an in-memory snapshot (no query per request). Blocking a principal deletes
their sessions (by sub, and by lowercased email), and lifting the block does not bring them back.
A block written by the offline CLI is picked up by the control plane's watcher and does the same.
Break-glass sessions are exempt from both checks.

A callback with a missing, unknown or expired `state` consumed nothing and writes no
row, and neither does a logout without a live session or one refused for CSRF. At most
20 `auth.login_failed` rows per client address are written per minute. At most 4,096
addresses are tracked at once; while all of them are inside their minute, a new
address writes no row either. Further attempts only increment an in-memory counter and
log `admin_audit_login_failed_rate_limited`, at most once a minute per address.
Successful logins are never rate-limited. The authorization code, `state`, PKCE
verifier, nonce, tokens and cookie values never appear in a row or a log line. If a
row cannot be appended, the entry is logged at ERROR with `persist_failed=true` and
the `admin_audit_degraded` alert is raised as above, but the sign-in or sign-out
itself still succeeds: it changes no admin state.

**Reading and verifying in the dashboard.** With the log on, the control plane
serves three read-only routes and an **Admin log** tab (separate from the receipts
**Audit** tab and its `/dashboard/api/audit*` routes). Off, or on a worker, all three
answer 404 and the tab stays hidden; the tab is also hidden from viewers and editors.
Nothing in the dashboard writes to the chain, and none of these routes is recorded.

| Route | Role (oidc) | What it returns |
|---|---|---|
| `GET /dashboard/api/admin-audit` | admin | `{entries, nextCursor}`, newest first |
| `POST /dashboard/api/admin-audit/verify` | admin | `{ok, checked, firstBadSeq, reason, headSeq, headHash, lastVerifiedSeq, partial}` |
| `GET /dashboard/api/admin-audit/pubkey` | any role | `{alg: "ed25519", keys: [{keyId, publicKey, firstSeq}]}` |

The list takes `actor` (a sub or an `actor_id`), `action`, `outcome` (`ok`,
`denied`, `rejected`, `error`), `since` (RFC3339), `limit` (1 to 200, default 50)
and `cursor`; a malformed value answers 400. Pass the returned `nextCursor` as
`cursor` for the next page; it is 0 on the last one. Each entry has the signed fields
(hashes in hex) plus the actor's plaintext sub and email from the side table, never
a signature or a request body.

Verify streams the chain and checks seq continuity, every `prev_hash` link, each
recomputed entry hash, each Ed25519 signature under the key its `key_id` names (keys
come from the chain's genesis and `segment_start` entries), that the key changes only
at a `segment_start`, and the signed `actor_id` against the side table with the
control plane's HMAC key. The optional body `{fromSeq, anchor: {seq, hash}}` starts
at `fromSeq` and compares the entry at `anchor.seq` with a hex entry hash you saw
earlier (for example the head of an emitted log line), which also detects a deleted
tail. One call checks at most 10,000 rows: when `partial` is true, call again with
`fromSeq` = `lastVerifiedSeq + 1` (the tab does this for you). On failure `ok` is
false, `firstBadSeq` is the first row that does not verify and `reason` names the
check (`entry_hash`, `prev_hash`, `signature`, `seq_gap`, `actor_id`,
`anchor_mismatch`, ...); the control plane also logs it at WARN. One verification
runs at a time; a concurrent call answers 429. In `console.auth: none` the verify
POST, like every dashboard POST, needs the `--admin-token-env` bearer.

The pubkey route lists every key the chain declares, so entries signed before a
manual key change stay verifiable; the tab shows each key with a copy button.

Offline CLIs that change admin state record through the same chain with
`adminaudit.OpenForCLI`: actor `cli:<os user>`, auth_method `cli`, the same key
check, and never a new key while rows exist. On a state dir where audit was never
enabled they skip the record with a notice.

**Hand edits of the served YAML.** In the default file policy-store mode, when the
3-second re-read finds served-config bytes that no control-plane writer produced,
the control plane still serves them and appends one `config.external_change` row
(auth_method `system`, target `policy`, before `file:<old sha256>`, after
`file:<new sha256>`), once per distinct file hash; the row and its log line carry
only the two hashes, never the file's content or path.

#### Anchoring the audit chain

The hash chain proves the rows agree with each other, but someone who can write the
state dir can still delete the newest rows or restore an older backup, and the shorter
chain still verifies. To catch that, the control plane also writes the chain to its log
(stdout, at INFO whatever `logLevel` says), as `schema=warden.admin.v1` lines:

- `msg=admin_audit`, one per committed entry, after its transaction commits: `seq`,
  `ts`, `entry_hash`, `prev_hash`, `key_id`, `actor_id`, `actor_sub`, `actor_email`,
  `actor_role`, `auth_method`, `action`, `target`, `target_ref`, `outcome`,
  `http_status`, `before_hash`, `after_hash`, `client_ip`, `request_id` and `details`.
  The plaintext `actor_sub` and `actor_email` appear only here and in the side table,
  never in the signed bytes. Only the fields of a validated entry are written: no
  request body, bearer token or secret value.
- `msg=admin_audit.checkpoint`, the chain head (`head_seq`, `head_entry_hash`,
  `key_id`) at startup, every 5 minutes and at shutdown.

For a closed, versioned JSON copy of the same entries (and these checkpoints) that a shipper
can read without parsing the operational log, enable `audit.jsonLog`; see
[siem.md](siem.md#admin-stream).

Ship these lines off-host (your log collector or SIEM) where the control plane's state
dir cannot reach them. The newest `admin_audit.checkpoint` or `admin_audit` line you
hold is an anchor: verify the chain with `admin-audit verify --anchor <seq>:<entry_hash>`
(see "Offline verify and export" above). Verification fails with `anchor_missing` when the
chain no longer reaches that seq (rows deleted from the tail, or an older backup
restored) and `anchor_mismatch` when the entry at that seq has a different hash. A
log line that fails to write never fails or rolls back the admin change itself.

### Migrating from none to oidc

1. Add the `console:` block to the operator-owned `--config` file: `auth: oidc`, the
   `oidc` block (`issuer`, `clientSecretEnv`, `redirectURL`, and `internalIssuerURL`
   when the control plane reaches the IdP on a different origin than the browser) and
   `roles` mapping your IdP groups to `admin`, `editor` and `viewer`.
2. Put the client secret in the environment variable `oidc.clientSecretEnv` names.
3. Start the control plane with `--state-dir` on a writable volume (sessions and
   pending logins live in `<state-dir>/warden-cp.db`). Add `--require-console-auth`
   so a lost `console:` block fails startup instead of reopening the console.
4. Verify: the startup log no longer carries the `console.auth=none` warning; opening
   `/dashboard/` redirects to the IdP; after sign-in a viewer can read every tab but
   gets 403 on a policy change, and an admin can edit integrations, LLM providers and
   secrets. A request with only a bearer (`$WARDEN_CP_TOKEN` or `$WARDEN_CP_ADMIN_TOKEN`) gets 401 on
   `/dashboard/api/*` and `/central/secrets`, while workers keep pulling `/policy`.

Scripts that call `/central/secrets` with the admin (or shared) bearer stop working in oidc
mode: secret writes then need an admin session plus CSRF, so they go through the
admin's secret store tab in the dashboard until scoped API keys exist. Scripts that
write `/dashboard/api/*` with the bearer stop working for the same reason.

### Login routes

In `oidc` mode (with `--state-dir`) the control plane serves `GET /auth/login` and
`GET /auth/callback`; in `none` mode both are 404. Login is the authorization-code flow
with S256 PKCE, a random `state` and `nonce`, and a pending row in the state DB (10 minute
TTL, single use, at most 10,000 rows). The row is bound to the browser by a short-lived
`__Host-warden_login` cookie (`warden_login` on an http loopback redirect URL). The ID
token must pass the shared verifier with `aud` = `oidc.clientID`, an `azp` equal to it
when present (required when `aud` has several entries), RS256 or ES256 only, and the
nonce. The user then needs a role from `console.roles`; the session id is minted by the
control plane after both checks and never taken from the request. No access, refresh or
ID token is stored, and `offline_access` is not requested. `next` is honoured only as a
path under `/dashboard/`. A failed login redirects to `/dashboard/?login_error=<code>` with
a code from `state_invalid`, `nonce_mismatch`, `token_invalid`, `exchange_failed`,
`idp_error`, `no_role` or `idp_unavailable`; IdP error text is never echoed. `/auth/login`
itself answers 503 `login_busy` when 10,000 logins are pending and 500 `login_error`
if the attempt cannot be stored. At most 256 groups are read from the token. Discovery
runs in the background with backoff, so an unreachable IdP never blocks startup or
`/policy`; until it succeeds both routes answer 503 `idp_unavailable`. Each attempt logs
one `console_login` line (`result`, `reason`, `sub`, `duration_ms`), never a code, state,
verifier, nonce or token.

## Consent sign-in config (`consent:`)

The `consent:` block configures the employee consent portal's sign-in: a
dedicated `warden-portal` OIDC client, separate from the console's. Like
`console:` it is control-plane-local: read from `--config` only (never the
served copy under `--state-dir`, where a different block is ignored with a
warning), never sent to workers, and kept byte-identical by the dashboard
writers. An absent block or `enabled: false` changes nothing and mounts no
route. This section covers the config surface; the portal routes arrive in
later tickets of the consent sign-in feature.

```yaml
consent:
  enabled: true
  oidc:
    issuer: https://idp.example.com        # must equal identity.issuer
    clientID: warden-portal                # default
    clientSecretEnv: WARDEN_PORTAL_DEX_CLIENT_SECRET   # env var NAME, never the secret
    redirectURL: https://warden.example.com/portal/callback  # path exactly /portal/callback
    # internalIssuerURL: http://dex:5556   # development split-horizon only
  allowedGroups: []                        # empty: any user of the issuer
  session:
    idle: 30m                              # 0 < idle <= absolute <= 24h
    absolute: 8h
  idpLink:
    enabled: true                          # request offline_access, keep the refresh token
    refreshLifetime: 720h                  # the IdP's absolute refresh lifetime
```

- Scopes are fixed: `openid email profile groups`, plus `offline_access` while
  `idpLink` is enabled.
- The session defaults are shorter than the console's (1h / 12h) because a portal
  session can approve third-party access for agents.
- Startup refuses to run an enabled block unless `console.auth` is `oidc`,
  `--state-dir` is set, the `clientSecretEnv` variable is non-empty (the error
  names the variable, never its value), and `consent.oidc.issuer` equals
  `identity.issuer` (a portal `sub` must match a data-plane `sub`). There is no dev
  or demo bypass: use the Dex compose recipe (`deploy/compose/dex`).
- While consent is enabled, a settings write that changes `identity.issuer` away
  from `consent.oidc.issuer` is refused with 400 `identity_issuer_mismatch`.
- `https` issuer unless `internalIssuerURL` is set; `redirectURL` is `https`
  unless its host is loopback, and must differ from `console.oidc.redirectURL`.
- `consent.store` is the CP-only user credential store; see
  [CP-only user credential store](#cp-only-user-credential-store-consentstore).

## API keys (`console.apiKeys`)

Scripts and CI can call the admin API with a scoped, expiring `wak_` key instead of
the shared `WARDEN_CP_TOKEN`. Each key acts for a human owner, holds only the scopes it
was created with, and is limited to the owner's *current* console role: the role is
recomputed on every request from the groups saved with the key and the live
`console.roles`, so moving the owner's group to a lower role takes effect at the next
restart. With `console.apiKeys.enabled: false` (the default) no table, middleware or
goroutine exists and a `wak_` bearer is just an unrecognised bearer.

Present a key as `Authorization: Bearer wak_...` on `/dashboard/api/*` only:

- Any query parameter whose name or value starts with `wak_` is `400 api_key_in_query`
  (a URL lands in logs); more than one `Authorization` header is `400
  multiple_authorization`; a key together with the console
  session cookie is `400 ambiguous_credentials`. A failed key (malformed, unknown,
  wrong secret, expired, revoked) is the same `401 {"error":"unauthorized"}` with
  `WWW-Authenticate: Bearer`, and never falls back to a session.
- A key request with no cookie skips the CSRF header and Origin checks.
- Each route's scope is the **API key scope** column of the [role matrix](#console-roles-and-the-role-matrix).
  A route whose scope the key lacks, whose scope is `none`, or whose minimum role the
  owner no longer holds answers `403 {"error":"insufficient_scope","need":"<scope>"}`.
  A route with no table row is never reachable by a key, so a new route stays closed
  until it is classified.
- A key whose owner is on the [block list](#block-list) is refused at once with the same
  403 (reads and writes), like the owner's sessions; lifting the block restores it.
- A key may make `ratePerKey` requests per second (burst 2x); over that is `429` with
  `Retry-After`. A throttled request writes no audit row.

With admin audit on, a key-made change is one row with `auth_method` `apikey`: the
actor is the key's owner (`actor_id` is the HMAC of the owner's sub, the side row holds
their sub and email, `actor_role` is the owner's current role) and `details.api_key_id`
names the key. A valid key that is refused is chained as `denied`. An invalid key writes
no row: it is counted, and logged as `apikey_auth_rejected` (the parsed key id or
`malformed`, the reason and `client_ip`, at most once a minute per address). Neither the
token nor its hash is ever logged or recorded. The in-memory counter
`warden_cp_apikey_auth_total{outcome}` (`ok`, `malformed`, `unknown`, `bad_secret`,
`expired`, `revoked`, `insufficient_scope`, `rate_limited`, plus `index_stale`) has no
per-key label.

Keys live in `<state-dir>/warden-cp.db` (table `api_keys`, created only when the feature
is on). The control plane authenticates from an in-memory index that it reloads within
2 seconds of a change another process makes, so a key revoked with the offline CLI is
refused by the running control plane at the next poll. If the index cannot confirm it is
current for 30 seconds it refuses every key (fail closed) rather than risk accepting one
revoked elsewhere. Last-use time and address are kept in memory and written every 60
seconds and at shutdown.

### Enabling, creating and expiring keys

Add the block to the operator-owned `--config` file (a commented copy with the
defaults is in `configs/config.control-plane.yaml`) and restart. Keys need
`console.auth: oidc` and `--state-dir`; startup names whichever is missing.

```yaml
console:
  auth: oidc
  apiKeys:
    enabled: true
    defaultTTL: 2160h   # 90 days when the request names no expiry
    maxTTL: 8760h       # hard ceiling; a longer request is 400
    maxPerOwner: 25     # active keys one owner may hold; the 26th is 409
    ratePerKey: 10      # requests per second per key (burst 2x)
```

A key has the form `wak_<16 hex id>_<52 character secret>`. Only a hash of the
secret is stored, and the full key is shown once, in the `201` that creates it.
Keys are created from a signed-in console session only: a key, a break-glass
session and an unauthenticated caller cannot mint one (`403 session_required`).
The console API Keys tab (#263) is the normal way to create, list and revoke keys;
see that tab's own documentation (the console tab ships with #263). The same routes
work from any HTTP client that holds a session.

- **Scopes.** A key holds the scopes it was created with and nothing else. The
  creator may only grant scopes their own role allows (`403 scope_exceeds_role`
  lists the ones that exceed it). At request time the key also needs the owner's
  *current* role to meet the route's minimum role. That role comes from the IdP
  groups saved with the key when it was created, mapped through the live
  `console.roles`: changing a group's mapping in `console.roles` (after a restart)
  narrows the keys of its members, but later IdP group changes do not reach existing
  keys, so offboarding someone needs a revoke by owner (`DELETE
  /dashboard/api/api-keys?owner_sub=<sub>` or `warden control-plane api-key revoke
  --owner-sub`).
- **Expiry.** `expiresIn` is a Go duration between `1h` and `maxTTL`; omit it for
  `defaultTTL`. A key cannot be extended: create a new one.
- **Names.** A name is 1 to 64 characters and unique per owner, including revoked
  keys (`409 name_taken`).

#### API key scopes

One row per scope a key can hold today. The table is pinned to the code by
`TestScopesDocumented`. The routes each scope opens, and the minimum role of each
route, are the **API key scope** column of the generated
[role matrix](#console-roles-and-the-role-matrix); this table does not repeat it.
A route's own minimum role can be higher than its scope's (for example the
blocked-users reads need admin although they take `policy:read`).

<!-- api-key-scopes:start -->
| Scope | Minimum role | What it covers |
|---|---|---|
| `policy:read` | viewer | Read the policy, its versions and diffs, change drafts, detection config and the block list. |
| `policy:draft` | editor | Create a change draft (`POST /dashboard/api/changes`). |
| `policy:write` | editor | Write the policy and detection config, update, submit, withdraw, rebase and replay drafts, edit the block list. |
| `settings:read` | viewer | Read settings (`GET /dashboard/api/settings`). Settings writes are session-only. |
| `traffic:read` | viewer | Traffic, endpoints, analytics, MCP, workers, the query endpoints and alerts. |
| `audit:read` | viewer | The traffic audit log and its verify call. |
| `adminaudit:read` | admin | The admin audit log, its verify call and its public key. |
| `agents:read` | admin | List and read agents in the registry. |
| `agents:write` | admin | Create, update, enable and disable agents. |
| `workers:admin` | admin | Revoke a worker certificate (`POST /dashboard/api/workers/{id}/revoke`). |
<!-- api-key-scopes:end -->

Scope names for later features (`mcp:read`, `mcp:write`, `grants:read`,
`grants:write`) are reserved and cannot be requested until their feature ships.

**Never keyable.** These answer a key `403 insufficient_scope` (with `need: none`),
or `401` where noted, whatever scopes it holds:

- key management itself (list, create, revoke; only `GET /dashboard/api/api-keys/self`
  is open to a key), sessions, token sessions, setup, backup, break-glass;
- policy rollback and the `PUT` variants of policy and detection (only `POST` is
  scoped, as `policy:write`), signing-keys routes, `query/generate`;
- change approve, reject, review and emergency apply;
- `/central/secrets*` including `GET`, secret-store, integrations and llmproviders
  reads and writes, and settings writes: these stay session-only in P2;
- worker-token create, list and revoke;
- every other route classified `none`.

The worker routes (`/policy`, `/control/*`, `/central/ingest`) refuse a `wak_`
bearer with `401`, and `/dashboard/` and `/auth/me` answer a key `401`. A route with
no table row is closed to keys until someone classifies it. The **API key scope**
column of the [role matrix](#console-roles-and-the-role-matrix) is the source of
truth: `none` means never keyable.

### Using a key in CI

Keep the key in a CI secret named `WARDEN_API_KEY` and send it as a bearer token
over HTTPS. Never put it in a URL (`400 api_key_in_query`). Later features (GitOps,
the admin MCP) use the same variable name.

```sh
export WARDEN_CP=https://warden-cp.example.com   # the control plane's base URL
```

Each example shows the request, the status and the body. `$WARDEN_API_KEY` stands
for a key like `wak_6127c9843b4791dd_kpvx…`; the examples use the key id
`6127c9843b4791dd`.

**200 read.** A `policy:read` key reads the policy.

```sh
curl -sS -i "$WARDEN_CP/dashboard/api/policy" -H "Authorization: Bearer $WARDEN_API_KEY"
```
```
HTTP/1.1 200 OK
Content-Type: application/json

{"allowlist":[{"domain":"api.openai.com","port":0}],"denylist":[{"domain":"evil.example.com","port":0}],"lint":[],"editable":true,"drift":false}
```

**200 introspect.** Any valid key can ask what it is allowed to do.
`effectiveScopes` is `scopes` capped by the owner's current role. The secret is
never returned.

```sh
curl -sS -i "$WARDEN_CP/dashboard/api/api-keys/self" -H "Authorization: Bearer $WARDEN_API_KEY"
```
```
HTTP/1.1 200 OK
Cache-Control: no-store

{"id":"6127c9843b4791dd","name":"ci","description":"deploys","scopes":["policy:read"],"effectiveScopes":["policy:read"],"ownerEmail":"eve@example.com","createdAt":"2027-01-15T08:00:00Z","expiresAt":"2027-02-14T08:00:00Z","lastUsedAt":"2027-01-15T08:00:00Z","status":"active"}
```

**201 create.** From a signed-in console session (cookie plus the CSRF header, as
the console sends it; a key cannot do this).

```sh
curl -sS -i -X POST "$WARDEN_CP/dashboard/api/api-keys" \
  -H "Cookie: $SESSION_COOKIE" -H "X-Warden-CSRF: $CSRF" -H 'Content-Type: application/json' \
  -d '{"name":"ci","description":"deploys","scopes":["policy:read"],"expiresIn":"720h"}'
```
```
HTTP/1.1 201 Created
Cache-Control: no-store

{"id":"6127c9843b4791dd","name":"ci","scopes":["policy:read"],"createdAt":"2027-01-15T08:00:00Z","expiresAt":"2027-02-14T08:00:00Z","key":"wak_6127c9843b4791dd_kpvx…"}
```

**400 bad request.** Invalid input, an unknown scope, a key in the query string,
two `Authorization` headers, or a key sent with a session cookie
(`ambiguous_credentials`).

```sh
curl -sS -i "$WARDEN_CP/dashboard/api/policy?token=wak_0123456789abcdef_<redacted>"
```
```
HTTP/1.1 400 Bad Request

{"error":"api_key_in_query"}
```

A key that was ever sent in a URL is leaked (proxy and access logs keep URLs): revoke it and rotate.

```sh
curl -sS -i -X POST "$WARDEN_CP/dashboard/api/api-keys" -H "Cookie: $SESSION_COOKIE" \
  -H "X-Warden-CSRF: $CSRF" -H 'Content-Type: application/json' -d '{"name":"ci","scopes":["bogus:scope"]}'
```
```
HTTP/1.1 400 Bad Request

{"detail":"apikeys: unknown scope: \"bogus:scope\"","error":"unknown_scope"}
```

**401 unauthorized.** Malformed, unknown, wrong secret, expired and revoked keys
all look the same, so a caller learns nothing about which it was. The same applies
to a key on a worker route (`/policy`), where the body is the worker plane's.

```sh
curl -sS -i "$WARDEN_CP/dashboard/api/policy" -H "Authorization: Bearer $WARDEN_API_KEY"
```
```
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Bearer

{"error":"unauthorized"}
```

**403 forbidden.** A valid key without the scope. `need` names it; for a route no
key may reach it is `none`.

```sh
curl -sS -i -X POST "$WARDEN_CP/dashboard/api/policy" -H "Authorization: Bearer $WARDEN_API_KEY" \
  -H 'Content-Type: application/json' -d '{"allowlist":[],"denylist":[]}'
```
```
HTTP/1.1 403 Forbidden

{"error":"insufficient_scope","need":"policy:write"}
```

```sh
curl -sS -i "$WARDEN_CP/central/secrets" -H "Authorization: Bearer $WARDEN_API_KEY"
```
```
HTTP/1.1 403 Forbidden

{"error":"insufficient_scope","need":"none"}
```

**404 not found.** An unknown or malformed key id on revoke.

```sh
curl -sS -i -X DELETE "$WARDEN_CP/dashboard/api/api-keys/0123456789abcdef" \
  -H "Cookie: $SESSION_COOKIE" -H "X-Warden-CSRF: $CSRF"
```
```
HTTP/1.1 404 Not Found

{"error":"api_key_not_found"}
```

**409 conflict.** A name already used by one of the owner's keys (`name_taken`), or
the owner already holds `maxPerOwner` active keys (`too_many_keys`).

```sh
curl -sS -i -X POST "$WARDEN_CP/dashboard/api/api-keys" -H "Cookie: $SESSION_COOKIE" \
  -H "X-Warden-CSRF: $CSRF" -H 'Content-Type: application/json' -d '{"name":"ci","scopes":["policy:read"]}'
```
```
HTTP/1.1 409 Conflict

{"error":"name_taken"}
```

**429 too many requests.** More than `ratePerKey` requests per second (burst 2x)
on one key. Wait `Retry-After` seconds.

```sh
curl -sS -i "$WARDEN_CP/dashboard/api/policy" -H "Authorization: Bearer $WARDEN_API_KEY"
```
```
HTTP/1.1 429 Too Many Requests
Retry-After: 1

{"error":"rate_limited"}
```

### Rotating a key

1. Create the new key (same scopes, new name, for example `ci-2027-02`) from the
   console or the create call above.
2. Put it in the CI secret store as `WARDEN_API_KEY` and redeploy or re-run the
   jobs that use it.
3. Check the old key is no longer in use: `GET /dashboard/api/api-keys` shows
   each key's `lastUsedAt` (kept in memory and written every 60 seconds).
4. Revoke the old key: `DELETE /dashboard/api/api-keys/{id}` from its owner's
   session (or any admin's). The next request with it is `401`. Revoking twice is
   `204` and changes nothing.

An admin can revoke every key of one owner with `DELETE
/dashboard/api/api-keys?owner_sub=<sub>`, for example when someone leaves. Blocking
a user on the [block list](#block-list) also refuses their keys at once, and
lifting the block restores them.

### Incident: offline revoke and restore

When the console is unavailable or a key has leaked, revoke from the host, with the
control plane running or stopped. The command opens `<state-dir>/warden-cp.db`
directly, creates no key and never prints a secret or hash. A running control plane
refuses the key within 2 seconds.

```sh
warden control-plane api-key list --state-dir /data [--json]
warden control-plane api-key revoke --state-dir /data --id 6127c9843b4791dd
warden control-plane api-key revoke --state-dir /data --owner-sub <sub>
```

`--admin-audit-key-file` names the admin audit signing key when it is not at
`<state-dir>/cp-audit.key`. Each revoke is one admin audit row (`api_key.revoke` or `api_key.revoke_owner`,
auth method `cli`, actor `cli:<os user>`) when admin audit is enabled in the state
dir. Exit codes: 0 done (including an already revoked key), 1 a refusal or an audit
failure after the revoke, 2 usage.

Restoring an older [backup](#scheduled-backups---backup-dir) brings back keys
revoked after it was taken. Re-apply those revocations from the shipped
`admin_audit` log, or restore with `--revoke-api-keys`, which revokes every key in
the restored database before it is put in place and records the count as
`api_keys_revoked` in the `cp.restore` audit row. Owners then create new keys. See
[backup and restore](runbooks/backup-restore.md).

```sh
warden control-plane restore --from /backups/20270115T080000Z --state-dir /data --force --revoke-api-keys
```

### Expiry warnings

With `console.apiKeys.enabled`, the control plane scans once an hour for unrevoked
keys that expire within 7 days and publishes one `api_key_expiring` finding (medium
severity) per key to the configured alert sinks. The finding carries the key id,
name, owner email and expiry, never a secret. A key is reported once, and again only
if its expiry changes; a control plane restart warns once more.

### Known limits

- **DLP scans request bodies only.** With `dlp.wardenTokens: true` (off by default) the egress detector flags a `wak_` or `wwt_`
  token in a proxied request body to a third party. The same token in a header or
  query string, or in an MCP call, is not flagged.
- **Owner revokes do not record the owner.** The audit row of a revoke by owner
  (console or CLI) names the actor, the count and the action, but not which
  `owner_sub` was targeted. The list of keys before the revoke is the record.
- **The expiry alert resolves itself.** The stored `api_key_expiring` alert is
  auto-resolved 15 minutes after it is published, like every one-shot finding. The
  notification is the warning; the key list shows the expiry for as long as the key
  lives.
- **Owner role changes need a restart.** The owner's role comes from the groups
  saved with the key and the live `console.roles`, which are read at startup.
- Rate limits on key create and revoke are not in place yet (tracked with the
  session rate limits).

## Console roles and the role matrix

The console has two modes, chosen by `console.auth`:

| | `none` (default) | `oidc` |
|---|---|---|
| Who you are | nobody: there is no sign-in | an IdP user with a server-side session (cookie) |
| Reads | open reads: any client that reaches `:7070` | need a session with at least `viewer` |
| Writes | gated by the CP admin bearer (`Authorization: Bearer`, [above](#dashboard-writes-need-the-control-plane-token)) | need a session, the role in the matrix below and the session's CSRF token (`X-Warden-CSRF`, from `GET /auth/me`) |
| Shared tokens | the bearer is the write credential | the shared tokens never open a human route, the bearer included |
| `/auth/me`, `/auth/logout` | absent (`404`) | any live session; logout is CSRF-checked and ends only the console session, not the IdP's |

**Break-glass login.** With `console.breakGlass.enabled` (and `console.auth: oidc`),
`POST /auth/breakglass` with `{"username","password"}` (JSON, at most 4 KiB, same-origin)
opens an admin session for when the IdP is down. It is not CSRF-checked (there is no
session yet) and answers `404` when break-glass is off. Failures are limited to 5 per
client address (`RemoteAddr`, never `X-Forwarded-For`) and 20 in total per 15 minutes;
a limited request answers `429 {"error":"rate_limited"}` with `Retry-After` and never
runs argon2id, and at most two verifications run at once (`429 {"error":"busy"}`). A
wrong username and a wrong password are indistinguishable (`401
{"error":"invalid_credentials"}`, one argon2id run each). The session has role `admin`,
`auth_method` `breakglass`, an absolute expiry of `sessionTTL` that activity never
extends, and a `Secure` cookie even behind a TLS terminator; a new login revokes the
earlier break-glass session. The hash is re-read on every attempt (`503
breakglass_unavailable` when it cannot be read). Every attempt logs one ERROR line
`breakglass_login` (outcome, client address and, on success, the 8-character session
hash), and publishes a `breakglass_login` Finding: critical per login, high for
failures. With admin audit on, a row that cannot be written fails the login closed (`503
audit_unavailable`). The limiter is in memory: its windows reset when the control plane
restarts. The password and the submitted username are never stored or logged.

The step-by-step procedure (generate the hash, log in during a Dex outage, rotate it
afterwards) is the [break-glass runbook](runbooks/break-glass.md).

Enabling break-glass is guarded at startup. The control plane refuses to start when
`--state-dir` is empty, when the hash does not load or is outside the argon2id bounds (the
error names `console.breakGlass.passwordHashEnv` or `passwordHashFile`, never the value),
and when it would serve plain HTTP (no `--ca-cert`/`--ca-key`) on a non-loopback `--listen`
address (`0.0.0.0`, `::`, an empty host such as `:7070`, any non-loopback IP or hostname)
unless `console.breakGlass.allowBehindTLSTerminator` is true. It logs a WARN at startup when
no alert pipeline exists or no integration's `alerts.match` routes a critical
`breakglass_login` Finding, and when `console.adminAudit.enabled` is false. While a
break-glass session is live it logs the WARN `breakglass_session_active` (count and earliest
expiry, no session id) every 5 minutes, and the dashboard shows a red banner with the
expiry. The control plane starts, serves workers and accepts break-glass logins with the
IdP unreachable; `/auth/login` answers `503 idp_unavailable` until discovery succeeds.

Moving a deployment from `none` to `oidc` is covered in
[Migrating from none to oidc](#migrating-from-none-to-oidc).

**Roles.** The role is the highest of `admin` > `editor` > `viewer` whose
`console.roles` groups match the user's IdP groups. Roles are computed from the groups
in the login token and stored with the session, and the role is re-derived from the
current `console.roles` on every request, so a `console.roles` change applies after a
restart. A user demoted or removed in the IdP keeps their console role until the
session's idle (1h) or absolute (12h) expiry unless an admin revokes it with the
sessions API below. This is documented behaviour, not a bug: revocation is the
manual control for offboarding.

**Listing and revoking sessions** (admin, `oidc` mode only; `404` in `none` mode).
The *Console sessions* card on the Settings page uses the same API:

- `GET /dashboard/api/sessions` returns the live sessions, newest first:
  `[{handle, iss, sub, email, authMethod, createdAt, lastSeenAt, expiresAt, current}]`.
  `handle` is the hex sha256 of the session id, which cannot be used as a cookie; the
  raw id and the CSRF token are never returned. `current` marks the caller's session.
- `DELETE /dashboard/api/sessions?handle=<hex>` revokes one session (`404` if unknown);
  `DELETE /dashboard/api/sessions?sub=<sub>` revokes every session of that subject
  (`{"revoked": n}`, `0` is not an error). Send exactly one of the two (`400` otherwise).
  The next request with a revoked cookie gets `401`.
- Both need an admin session; `DELETE` also needs `X-Warden-CSRF`. The routes are
  served by the control plane ahead of the dashboard, so the shared and admin bearer
  tokens never reach them (`401` without a session). Each revoke logs
  `console_session_revoked` with `by_sub`, `target_sub` and `count` (and the first 8
  hex characters of a revoked handle), never a cookie value.

**The UI follows the role.** After `GET /auth/me` succeeds the dashboard shows the
signed-in email, the role and a *Log out* button, and hides every control whose
minimum role is above the user's (the `data-min-role` attribute in
`internal/dashboard/index.html`). Hiding is cosmetic: the server checks every request
against the table below. In `none` mode nothing is hidden and no user is shown.

**Role matrix** (`oidc` mode). Generated from the authz table; `TestAuthzMatrixDoc`
fails when the two differ.

<!-- authz-matrix:start -->
<!-- Generated from authzTable() and internal/config/settings_roles.go; do not edit by hand.
     Regenerate: go test ./internal/controlplane -run TestAuthzMatrixDoc -update -->

| Route | Method | Minimum role | Action | API key scope |
|---|---|---|---|---|
| `/dashboard/` | GET | viewer | `ui.read` | `none` |
| `/dashboard/api/admin-audit` | GET | admin | `adminaudit.read` | `adminaudit:read` |
| `/dashboard/api/admin-audit/pubkey` | GET | viewer | `adminaudit.pubkey` | `adminaudit:read` |
| `/dashboard/api/admin-audit/verify` | POST | admin | `adminaudit.verify` | `adminaudit:read` |
| `/dashboard/api/agents` | GET | viewer | `agent.list` | `agents:read` |
| `/dashboard/api/agents` | POST | admin | `agent.create` | `agents:write` |
| `/dashboard/api/agents/{id}` | GET | viewer | `agent.read` | `agents:read` |
| `/dashboard/api/agents/{id}` | PUT | admin | `agent.update` | `agents:write` |
| `/dashboard/api/agents/{id}/disable` | POST | admin | `agent.disable` | `agents:write` |
| `/dashboard/api/agents/{id}/enable` | POST | admin | `agent.enable` | `agents:write` |
| `/dashboard/api/alerts` | GET | viewer | `alerts.read` | `traffic:read` |
| `/dashboard/api/analytics` | GET | viewer | `analytics.read` | `traffic:read` |
| `/dashboard/api/api-keys` | GET | viewer | `api_key.list` | `none` |
| `/dashboard/api/api-keys` | POST | viewer | `api_key.create` | `none` |
| `/dashboard/api/api-keys` | DELETE | admin | `api_key.revoke_owner` | `none` |
| `/dashboard/api/api-keys/self` | GET | viewer | `api_key.self` | `self` |
| `/dashboard/api/api-keys/{id}` | DELETE | viewer | `api_key.revoke` | `none` |
| `/dashboard/api/audit` | GET | viewer | `audit.read` | `audit:read` |
| `/dashboard/api/audit/verify` | POST | viewer | `audit.verify` | `audit:read` |
| `/dashboard/api/backup` | POST | admin | `backup.run` | `none` |
| `/dashboard/api/blocked-users` | GET | admin | `blocked_users.read` | `policy:read` |
| `/dashboard/api/blocked-users` | POST | admin | `blocked_users.add` | `policy:write` |
| `/dashboard/api/blocked-users/{id}` | DELETE | admin | `blocked_users.remove` | `policy:write` |
| `/dashboard/api/changes` | GET | viewer | `change.draft.list` | `policy:read` |
| `/dashboard/api/changes` | POST | editor | `change.draft.create` | `policy:draft` |
| `/dashboard/api/changes/{id}` | GET | viewer | `change.draft.read` | `policy:read` |
| `/dashboard/api/changes/{id}` | PUT | editor | `change.draft.update` | `policy:write` |
| `/dashboard/api/changes/{id}/approve` | POST | editor | `change.draft.approve` | `none` |
| `/dashboard/api/changes/{id}/diff` | GET | viewer | `change.draft.diff` | `policy:read` |
| `/dashboard/api/changes/{id}/emergency-apply` | POST | admin | `change.draft.emergency_apply` | `none` |
| `/dashboard/api/changes/{id}/rebase` | POST | editor | `change.draft.rebase` | `policy:write` |
| `/dashboard/api/changes/{id}/reject` | POST | editor | `change.draft.reject` | `none` |
| `/dashboard/api/changes/{id}/replay` | POST | editor | `change.draft.replay` | `policy:write` |
| `/dashboard/api/changes/{id}/review` | POST | admin | `change.draft.review` | `none` |
| `/dashboard/api/changes/{id}/submit` | POST | editor | `change.draft.submit` | `policy:write` |
| `/dashboard/api/changes/{id}/withdraw` | POST | editor | `change.draft.withdraw` | `policy:write` |
| `/dashboard/api/detection` | GET | viewer | `detection.read` | `policy:read` |
| `/dashboard/api/detection` | POST | editor | `detection.write` | `policy:write` |
| `/dashboard/api/detection` | PUT | editor | `detection.write` | `none` |
| `/dashboard/api/endpoints` | GET | viewer | `endpoints.read` | `traffic:read` |
| `/dashboard/api/integrations` | GET | viewer | `integrations.read` | `none` |
| `/dashboard/api/integrations` | POST | admin | `integrations.write` | `none` |
| `/dashboard/api/integrations` | DELETE | admin | `integrations.delete` | `none` |
| `/dashboard/api/keys` | GET | admin | `keys.read` | `none` |
| `/dashboard/api/keys/rotate` | POST | admin | `keys.rotate_requested` | `none` |
| `/dashboard/api/llmproviders` | GET | viewer | `llmproviders.read` | `none` |
| `/dashboard/api/llmproviders` | POST | admin | `llmproviders.write` | `none` |
| `/dashboard/api/llmproviders` | PUT | admin | `llmproviders.write` | `none` |
| `/dashboard/api/mcp` | GET | viewer | `mcp.read` | `traffic:read` |
| `/dashboard/api/per-user-secrets` | PUT | admin | `per_user_secrets.write` | `none` |
| `/dashboard/api/policy` | GET | viewer | `policy.read` | `policy:read` |
| `/dashboard/api/policy` | POST | editor | `policy.write` | `policy:write` |
| `/dashboard/api/policy` | PUT | editor | `policy.write` | `none` |
| `/dashboard/api/policy/versions` | GET | viewer | `policy.versions.read` | `policy:read` |
| `/dashboard/api/policy/versions/{v}` | GET | viewer | `policy.version.read` | `policy:read` |
| `/dashboard/api/policy/versions/{v}/diff` | GET | viewer | `policy.diff` | `policy:read` |
| `/dashboard/api/policy/versions/{v}/rollback` | POST | editor | `policy.rollback` | `none` |
| `/dashboard/api/query` | POST | viewer | `query.run` | `traffic:read` |
| `/dashboard/api/query/generate` | POST | editor | `query.generate` | `none` |
| `/dashboard/api/query/schema` | GET | viewer | `query.schema` | `traffic:read` |
| `/dashboard/api/secrets` | GET | viewer | `secrets.read` | `none` |
| `/dashboard/api/secretstore` | GET | viewer | `secretstore.read` | `none` |
| `/dashboard/api/secretstore` | POST | admin | `secretstore.write` | `none` |
| `/dashboard/api/secretstore` | DELETE | admin | `secretstore.delete` | `none` |
| `/dashboard/api/sessions` | GET | admin | `sessions.read` | `none` |
| `/dashboard/api/sessions` | DELETE | admin | `sessions.revoke` | `none` |
| `/dashboard/api/settings` | GET | viewer | `settings.read` | `settings:read` |
| `/dashboard/api/settings` | POST | editor | `settings.write` | `none` |
| `/dashboard/api/settings` | PUT | editor | `settings.write` | `none` |
| `/dashboard/api/setup` | GET | viewer | `setup.read` | `none` |
| `/dashboard/api/token-sessions` | GET | admin | `token_sessions.read` | `none` |
| `/dashboard/api/token-sessions/revoke` | POST | admin | `token_sessions.revoke_all` | `none` |
| `/dashboard/api/token-sessions/{sid}/revoke` | POST | admin | `token_sessions.revoke` | `none` |
| `/dashboard/api/traffic` | GET | viewer | `traffic.read` | `traffic:read` |
| `/dashboard/api/worker-enrollments` | GET | admin | `worker_enroll_token.read` | `workers:admin` |
| `/dashboard/api/worker-enrollments` | POST | admin | `worker_enroll_token.create` | `none` |
| `/dashboard/api/worker-enrollments/{id}` | DELETE | admin | `worker_enroll_token.revoke` | `workers:admin` |
| `/dashboard/api/worker-tokens` | GET | viewer | `worker_token.read` | `none` |
| `/dashboard/api/worker-tokens` | POST | admin | `worker_token.create` | `none` |
| `/dashboard/api/worker-tokens/{id}` | DELETE | admin | `worker_token.revoke` | `none` |
| `/dashboard/api/workers` | GET | viewer | `workers.read` | `traffic:read` |
| `/dashboard/api/workers/{id}/revoke` | POST | admin | `worker.revoked` | `workers:admin` |

A method and path with no row is refused (`403`) for every role, `GET` included.

Settings writes (`POST`/`PUT /dashboard/api/settings`) are then checked per changed field:

- An editor may change only `advisory`, `agents`, `cacheTTLSeconds`, `compliance`, `dlp`, `logging`.
- Inside those, these subfields still need admin (list elements are matched by `id`): `agents[].identity`.
- Every other field needs admin, including any field added later.

`POST /dashboard/api/query/generate` is limited to 10 calls a minute per console session (`429` past it).
<!-- authz-matrix:end -->

## Policy history (`--policy-store`)

The allow/deny policy and the distributed settings can live in an append-only
versioned store in control-plane state instead of being edited in place in the
served YAML. Every save creates a new version with its author and message,
editors can diff any two versions and roll back, and workers are always served
the head version. The feature is off by default; see the release plan at the
end of this section.

### Turning it on

`warden control-plane --policy-store=file|versioned` picks where the policy
served on `/policy` comes from.

- `file` (the default) serves the served config YAML, exactly as before. With
  `--state-dir` the served YAML is a writable copy seeded once from `--config`
  (`<state-dir>/config.yaml`); without `--state-dir` the dashboard keeps
  editing `--config` in place.
- `versioned` serves the head of the version history in
  `<state-dir>/warden-cp.db` and requires `--state-dir`; without it, or with any
  other flag value, the control plane refuses to start.

### Version 1: the migration

The first versioned start on an empty store imports the served config's
allow/deny lists and settings as version 1 (author `system:import`, source
`import`, message `initial import from <served path>`). `/policy` serves the
same bytes and ETag before and after, so no worker sees a change. If the import
would change the ETag, the control plane refuses to start and leaves the store
empty; start with `--policy-store=file` and report it. A store that already has
versions is never re-imported, and two control planes racing the first start
import once. With `console.adminAudit.enabled` the import appends one
`policy.initial_import` admin audit row (target `policy`, auth_method `system`,
before `file:<sha256 of the served YAML>`, after `v1:<doc_sha256>`); a failed
append is logged at ERROR and does not stop startup.

### What a version holds, and what it never holds

- Each version holds the allow/deny lists and the distributed settings
  (including `llmProviders`), its parent version, the author (sub, email,
  kind), a message, the source (`import`, `policy`, `settings`,
  `llmproviders`, `rollback`) and the `doc_sha256` of the stored doc. Versions
  and the publish log are append-only: SQLite triggers refuse an UPDATE or
  DELETE.
- **Credential values are never stored.** An AWS `secretAccessKey` is kept in a
  version only as its fingerprint, `sha256:<16 hex>`; the live value stays in
  the served YAML `secretStore` block and is merged in when `/policy` is built,
  so workers get the same bytes as before. In history responses and diffs a
  credential appears only as its fingerprint, never the value.
- Serve-time overlay data is not stored either. The credential
  (versioned mode) and the user block list (whenever a state dir is set) are the
  overlays today. A rollback therefore never restores an old credential or
  block list.
- CP-local blocks (integrations, detection, `central`, `controlPlane`, ...)
  are not versioned; their editors keep rewriting the served YAML.

### Saves, authors and field ownership

- Dashboard saves of the policy, the settings form and the LLM providers each
  create a new version from the head (source `policy`, `settings` or
  `llmproviders`). Each writer changes only the fields it owns and carries
  every other field from the head: the policy save owns the allow/deny lists,
  the LLM providers save owns `llmProviders`, and the settings save owns the
  rest of the settings except `dlp` and `advisory`, which the settings form
  does not edit and which are always carried from the head (change them with
  `warden policy import`).
- An edit the config loader rejects (for example an empty allowlist) returns
  the loader error and creates no version; a save that changes nothing creates
  none either.
- The author is the signed-in user (sub and email, kind `oidc`),
  `breakglass:<username>` for a break-glass session, or `anonymous` (kind
  `none`) in `console.auth: none`, where the bearer proves possession of the
  shared token, not an identity.
- A settings save with an empty `secretAccessKey` keeps the live credential. A
  new value is written to the served YAML `secretStore` block (the only place
  the credential lives) and the version stores only its fingerprint; if the
  version cannot be created the YAML is put back.

### The version header, If-Match, 409 and 428

- Policy, settings and LLM providers share one head version. Their GETs
  (`/dashboard/api/policy`, `/dashboard/api/settings`,
  `/dashboard/api/llmproviders`) and `GET /dashboard/api/policy/versions`
  return it as `version` (`head` for the history list) in the body and in an
  `X-Warden-Policy-Version: N` header; in file mode neither is present.
  `/policy`'s content-hash ETag is unchanged.
- In versioned mode every save must send `If-Match: "v<N>"` with the version
  it was based on. If the head has moved since, the save returns `409
  {"error":"policy_conflict","head":M,"author":{"sub":...,"email":...}}` (the
  head's author, never doc content) and creates nothing, so a settings save
  makes a concurrent policy save from the same version conflict. A missing
  `If-Match` on a save or a rollback returns `428
  {"error":"precondition_required"}` and a malformed one 400; neither creates a
  version.
- A save may also send an optional message in `X-Warden-Policy-Message`,
  percent-encoded UTF-8 (as `encodeURIComponent` writes it), at most 512
  characters after decoding, with control characters stripped; it is stored on
  the new version, and a longer or badly encoded value returns 400.
- In file mode `If-Match` and `X-Warden-Policy-Message` are ignored and saves
  work as before.

### History, diff and rollback

In versioned mode the control plane serves these routes (in file mode they
answer 404). Reads need the viewer role and a rollback the editor role (see the
role matrix above).

| Route | What it returns |
|---|---|
| `GET /dashboard/api/policy/versions?cursor=&limit=` | `{"head":N,"versions":[...],"next_cursor":C}`: version metadata (version, parent, created_at, author_sub, author_email, author_kind, message, source, doc_sha256), newest first, 50 per page by default and at most 200; pass `next_cursor` as `cursor` for the next page (0 = no more). |
| `GET /dashboard/api/policy/versions/{v}` | One version's metadata and its `doc`, credential as a fingerprint. |
| `GET /dashboard/api/policy/versions/{v}/diff?against={u}` | `{"from":u,"to":v,"diff":{"allow":[...],"deny":[...],"settings":[...]}}`: the structural diff from `u` (default: the head) to `v`, by entry and settings path, each change `added`, `removed` or `changed`. With the default it is what a rollback to `v` would change. |
| `POST /dashboard/api/policy/versions/{v}/rollback` | Body `{"note":"..."}` (optional, at most 512 characters). Publishes version `v`'s doc as a **new** head version (source `rollback`, message `rollback to v<N>[: note]`); history is never rewritten. Returns `{"head":M,"changed":true}` and `X-Warden-Policy-Version: M`; a target equal to the head creates nothing (`changed: false`). |

A rollback keeps the head's credential fingerprint (the served credential does
not change), is revalidated with today's config loader (a target that no longer
validates answers `422 {"error":"invalid_policy"}` and creates nothing), and
uses the same conflict check as a save. An unknown version answers 404.

The console's Guardrails → Egress tab shows a History card on these routes in
versioned mode (hidden in file mode): versions newest first with author,
relative time, source and message, 20 at a time with "Load more"; selecting one
shows the server's structural diff from head to that version (added, removed
and changed entries and settings paths with old and new values); editors and
admins get a Roll back button that asks for confirmation naming the target
version and an optional note. The policy, settings and LLM provider saves ask
for an optional message and send `If-Match`; on a 409 the console says
`policy changed by <author> (v<N>)`, takes the new head and keeps the unsaved
edit on screen.

### The served YAML: write-through mirror and drift

- The served YAML is a write-through mirror of the head: after every head move
  (a dashboard save, a rollback, or a version from another process seen by the
  3-second check) the control plane renders the head's policy and settings
  blocks into it, with the live credential, through the same validated atomic
  write. So `--policy-store=file` or an older binary serves the same policy. A
  mirror failure (for example a read-only file) is logged at ERROR with the
  version and never fails the save.
- A hand edit of the YAML's policy or settings blocks is drift: it is never
  served. The 3-second check logs `served config policy block differs from
  head; ignored` (with `file_sha256`, the hash of those blocks, and `head`) once
  per distinct file hash, `GET /dashboard/api/policy` reports `drift: true` and
  the Guardrails page shows a banner. With `console.adminAudit.enabled` each
  distinct file hash appends one `config.external_change` row (before
  `v<head>:<doc_sha256>`, after `file:<file_sha256>`); the file-mode check in
  the admin audit section is not used. Edits to the credential or to CP-local
  blocks are not drift. Bring an edit in with `warden policy import`; putting
  the file back, or the next save, clears the drift.
- The first check after a restart does not write the file: it compares the file
  with what the head would render to, so an edit made while the control plane
  was down shows as drift instead of being overwritten.
- The control plane checks for a new head every 3 seconds and only re-reads a
  version when the head moved, so a version written by another process reaches
  workers within 3 seconds plus one long-poll cycle. The `/policy` hot path
  never reads the database.
- Startup fails closed: if the store cannot be read, the head points at a
  missing version, or a version fails its `doc_sha256` check, the control plane
  refuses to start and never falls back to the YAML. A read error at runtime
  keeps serving the last good policy and logs a warning.

### `warden policy import` and `warden policy export`

- `warden policy import --state-dir <dir> --file <yaml> [--message m]
  [--admin-audit-key-file F] [--expected-head N]` stores a config YAML's
  policy, settings and llmProviders blocks as a new version, with the control
  plane running or stopped. The file is loaded strictly (an unknown key is an
  error) and checked like a dashboard write, against the file itself and
  against `<dir>/config.yaml` when it exists. A raw `secretAccessKey` is stored
  as its fingerprint; it must match the served config's credential, because the
  store cannot carry a new value (change the credential in the served config
  instead). A file without the credential is refused while the served config
  has one, so an unedited export cannot drop it. The version is authored
  `cli:<os user>` with source `import`, and is created by compare-and-swap from
  the current head (or `--expected-head`): a moved head exits non-zero naming
  the new head, and a file equal to the head prints `no change` and exits 0.
  The state dir must already hold the store (any control plane of this version
  started with `--state-dir` creates it). When admin audit has rows in the
  state dir, the import appends a `policy.import` row (actor `cli:<os user>`,
  auth_method `cli`, target `policy`, before `v<head>:<doc_sha256>`, after
  `v<new>:<doc_sha256>`); a missing or mismatching key file aborts before the
  version is written. Without admin audit it prints a one-line notice.
- `warden policy export --state-dir <dir> [--version N]` opens the database
  read-only and writes one version (default: the head) to stdout as a config
  YAML (policy, the settings blocks and llmProviders) that the loader accepts,
  for a downgrade, disaster recovery or a GitOps hand-off. Credential values and
  fingerprints are never written: a version with an AWS credential is exported
  without `secretStore.aws.accessKeyId`/`secretAccessKey`, with a note on
  stderr; add them back before you serve or re-import the file.

### Fleet policy version

Every head move appends a publish-log row with the `/policy` ETag it serves. A
served-ETag change without a new version (an overlay change, such as the
credential edited in the served YAML, or a version recorded without the ETag
the control plane actually serves) is appended by the control plane on its next
refresh, with the overlay's name or `external` as the reason, and logged as
`policy publish logged`. The fleet view maps each worker's heartbeat ETag to the newest
version with that ETag and shows `v<N> · <etag>`
(`policyVersion` in `GET /dashboard/api/workers`); an ETag with no row, and
every worker in file mode, shows the bare ETag. The `behind` flag still
compares the worker's ETag with the one served now.

### What is audited

With `console.adminAudit.enabled`, these policy changes append admin audit
rows (target `policy`, before and after as `v<N>:<doc_sha256>` in versioned
mode):

- `policy.initial_import`: the version 1 migration (auth_method `system`).
- `policy.write`: a dashboard policy save, including a rejected 409 (outcome
  `rejected`); settings and LLM providers saves are `settings.write` and
  `llmproviders.write`.
- `policy.rollback`: a rollback.
- `policy.import`: `warden policy import` (auth_method `cli`).
- `config.external_change`: a hand edit of the served YAML (drift in versioned
  mode, a served change in file mode; auth_method `system`).

History reads and diffs are not audited. Credentials appear in history only as
fingerprints; audit rows carry only state hashes, and exports leave the
credential out.

### Downgrade

Because the served YAML mirrors the head, restarting with
`--policy-store=file` (or an older binary) serves the same policy. Edits made
in file mode go to the YAML only, not to the store; before switching back to
`versioned`, bring them in with `warden policy import`, or they show as drift
and are not served. `warden policy export` writes any version as a loadable
YAML if the mirror is lost.

### Release plan

- **Release N** (the first release with policy history) ships the versioned
  store only behind `--policy-store=versioned`; the default stays `file`.
- **Release N+1** flips the default to `versioned`. `--policy-store=file` stays
  as an explicit opt-out, and a control plane started without `--state-dir`
  keeps file mode with a startup WARN.
- **Release N+2** removes YAML as a policy source: `--policy-store=file` is
  removed, the served YAML is only the write-through mirror of head, and hand
  edits are never served (they come in through `warden policy import`).

## Change drafts and the two-person rule (`console.approvals`)

The operator guide, with the config keys, what is held, replay, the offline CLI and the
known limits, is [approvals.md](approvals.md).

With `console.approvals.enabled` (off by default; it needs `console.auth: oidc`, the
versioned policy store and the admin audit log) the control plane serves the change
draft API under `/dashboard/api/changes`. A draft is a proposed policy doc based on a
policy version. A change that widens what agents can reach, or where credentials go, is
published only after a second person approves it. Workers never serve these routes
(`404`).

### Which writes are gated

With approvals enabled, one clearance check (`approvals.Gate`) guards every write that
creates a policy version; the version funnel (`Server.publish`) refuses a write that
holds no clearance. A write that widens access (or, with `allowSelfApproveNarrowing`
off, any change) is stored as a pending draft and answered `202`
`{draft_id, revision, state, widening, reasons}` with a `Location` header naming the
draft; head is unchanged. A narrowing write applies at once (`200`). A stale `If-Match`
is still `409 policy_conflict` and a missing one `428`. Field-level role checks run at
save time and the draft's required role is checked again at approve time.

| Gated | Not gated |
|---|---|
| `POST`/`PUT /dashboard/api/policy`, `POST`/`PUT /dashboard/api/settings`, `POST`/`PUT /dashboard/api/llmproviders`, `POST /dashboard/api/policy/versions/{v}/rollback` (the draft's doc is version `v`, source `rollback`), and `warden policy import`. Also, as drafts of their own target (they create no policy version): `DELETE /dashboard/api/blocked-users/{id}` and `warden control-plane block remove` (target `blocked_users`); registering an agent, adding an allowed group or scope, adding or replacing a key, and re-enabling an agent through `POST`/`PUT /dashboard/api/agents` and `POST /dashboard/api/agents/{id}/enable` (target `agents`) | integrations, detection, the secret store (`/dashboard/api/secretstore`, `/central/secrets`; they write secret values, not a version), adding a block (the incident kill switch), disabling an agent and agent edits that only narrow (a removed group, a display name), worker tokens, signing keys, sessions, backups, the offline `agent` commands, and the offline commands below |

A `blocked_users` or `agents` draft publishes no policy version, so its approve
and emergency-apply results carry no `version` or `applied_version`; an agent's
new revision is on the agent (`GET /dashboard/api/agents/{id}`). The block list
is admin-only, so a non-admin (a viewer, or a `policy:read` key whose owner is not
an admin) reading such a draft sees `{id, has_sub, has_email}`, never who is blocked.

Not gated, stated plainly for production use:

- With approvals enabled, `warden control-plane block remove` holds the removal as
  a pending `blocked_users` draft (author `cli:<os user>`), prints the draft id and
  leaves the user blocked until a second admin approves it in the console. The
  offline `warden control-plane agent register|update|enable` commands are not yet
  held: with host access they still widen the agent registry without a second person.
- The offline `warden control-plane restore` can move the policy head back without
  approval.
- The first-start import of the served YAML as version 1 is not gated: it is proven
  safe by checking that the served `/policy` ETag is unchanged, and it runs only on an
  empty store.
- `/central/secrets` and `/dashboard/api/secretstore` write secret values into the
  managed secret store, not into a policy version.

### Emergency apply and its review

With `approvals.allowEmergencyApply: true`, a break-glass session (and only one) may
`POST /dashboard/api/changes/{id}/emergency-apply {"reason": "..."}` (10 to 512
characters) on a pending or needs_rebase draft. It publishes with `expectedHead` still
checked (`409 rebase_required` on a moved head), at most 5 times in 10 minutes. The
claim and an `emergency` approval row holding the reason are written together, and the
`change.draft.emergency_begin` admin audit row is written before anything publishes
(if it cannot be written nothing publishes). Every success raises one critical
`approval_bypassed` Finding and one ERROR log line; the draft is then `applied_unreviewed`.
If the version published but the draft could not be updated, the request fails with
`500 emergency_apply_unrecorded`, still alerts and still writes its `policy.write` audit
row (the 500 request row is kept). At every start the control plane raises the
`approval_bypassed` Finding again for each draft still `applied_unreviewed` (repeats
share the DedupKey `approval_bypassed:<draft id>`), and settles an interrupted draft.
A crash between the publish and the draft update is different: no request row or
`policy.write` row is written even after the repair, so look in policy history for a
version authored by the break-glass actor (author kind `breakglass`).

`POST /dashboard/api/changes/{id}/review {"comment": "..."}` (at least 10 characters)
closes it as `applied`. It needs an OIDC admin who is not a break-glass session and
who is not the draft's author (`403 self_review_forbidden`): in a single-admin
deployment the author's own bypass stays `applied_unreviewed`, because the alert has
already gone out and the review is meant to be independent.

A draft created by `warden policy import` is authored `cli:<os user>` and carries no
issuer. Anyone with host access to the state database already has full trust over the
control plane, so this is a limitation of what the offline CLI can prove, not a bypass
of the gate.

A settings save that carries a new raw `secretAccessKey` is refused (`422`/`400`
naming the credential) instead of becoming a draft: a draft holds only the
fingerprint. Change the credential in the served config first. If approvals are
enabled but the approvals service is missing, every gated write is refused with
`503 approvals_unavailable`.

`warden policy import` with approvals enabled (the control plane records this in the
single-row `approvals_meta` table at every start) creates a pending draft authored
`cli:<os user>` (source `cli`), prints its id, appends a `policy.import` admin audit
row and leaves head alone. The CLI cannot approve or apply; the control plane queues
the draft's replay on its next sweep (within a minute).

| Route | Who |
|---|---|
| `GET /dashboard/api/changes?target=&state=&cursor=&limit=` | viewer |
| `GET /dashboard/api/changes/{id}`, `GET .../{id}/diff` | viewer |
| `POST /dashboard/api/changes` (`If-Match: "v<base>"`) | editor |
| `PUT .../{id}` (`If-Match: "r<rev>"`), `POST .../{id}/submit`, `withdraw`, `rebase` | the draft's author (editor) |
| `POST .../{id}/approve`, `POST .../{id}/reject` | editor; approve also needs the draft's required role |
| `POST .../{id}/replay` | editor |

- **Revisions.** Every edit is a new revision (`ETag: "r<N>"`) and voids the earlier
  revisions' approvals. A body is capped at 1 MiB and a comment at 1024 characters
  (control characters are stripped).
- **Approve** takes `{revision, doc_sha256, replay_id | acknowledgeNoReplay, comment}`.
  `409 revision_changed` when the revision or digest differ from the draft;
  `409 replay_required` unless `replay_id` names a done replay of this revision no older
  than `replayMaxAge`, or `acknowledgeNoReplay` is true and the revision's latest replay
  failed or was unavailable. A revision whose replay never ran (queueing it failed) gets
  an `unavailable` replay row; one with no row at all is `replay_required` (re-run it
  with `POST .../replay`).
- **Reject.** Rejecting needs editor only, not the draft's required role: rejecting can
  only stop a change, so editor suffices.
- **Expiry.** An open draft past its expiry cannot be approved or applied
  (`409 illegal_transition`, `reason: expired`) even before the sweeper retires it.
- **Two-person rule.** The approver's subject must differ from the author's
  (`403 self_approval_forbidden`); a break-glass session never approves
  (`403 breakglass_cannot_approve`); the approver must hold the draft's required role now
  (`403 role_required`, naming the settings fields that need admin). With
  `minApprovals > 1` the approvers must be distinct.
- **API keys.** A key reaches the draft routes with the scopes in the
  [role matrix](#console-roles-and-the-role-matrix): `policy:read` to read,
  `policy:draft` to create, `policy:write` to edit, submit, withdraw, rebase and
  replay. No key can approve or reject (`403 insufficient_scope`): the second person is
  always a signed-in human. A key acts as its owner, so a draft made with u1's key is
  u1's draft (recorded with author kind `apikey`) and u1's own session cannot approve
  it (`403 self_approval_forbidden`).
- **Apply.** The approval that completes the set publishes the draft in the same
  request: `200 {state: applied, version}`. A moved head is `409 rebase_required {head}`
  (the draft becomes `needs_rebase`); a doc the loader refuses is `422` and the draft
  stays pending. A narrowing draft with `allowSelfApproveNarrowing` applies at submit
  with decision `self` (no replay is queued for it).
- **Rebase** replays the draft's change (base version to doc) onto the live head as
  revision n+1, or answers `409 rebase_conflict` naming the keys changed on both sides.
- **Audit.** Every mutation is an admin audit row (`change.draft.<verb>`, target
  `change_draft`, target_ref `draft:<id>@r<rev>`, details: base and applied version,
  widening, reason codes, replay status), never doc content. Submitting a widening draft
  publishes an info Finding `policy_approval_requested`. When an approval (or a
  self-applied submit) publishes, a second row follows: `policy.write` on target `policy`
  with `applied_version`, `source: approval` and the policy hashes before and after, the
  actor being the approver.
- **Validation.** A draft doc is dry-run through the config loader at create and edit
  (`422 invalid_policy`), and again at apply.

## Scheduled backups (`--backup-dir`)

Off by default. With `--backup-dir` (which needs `--state-dir` and must not be
inside it) the control plane writes a backup set at startup when none is newer
than the interval, then every `--backup-interval` (default 24h, minimum 1h)
after the newest set, on one background goroutine; a restart does not skip a
due backup. `--backup-keep` (default 7, minimum 1) newest complete sets are
kept; `--backup-include` picks from `cp`, `alerts`, `config` and `fleet`
(default `cp,alerts,config`; `fleet` is opt-in).

The drill (copy sets off host, `warden control-plane restore`, re-applying what
happened after the set) is the [backup and restore runbook](runbooks/backup-restore.md).

Each set is a directory named `<UTC time>Z` (`20060102T150405Z`) holding a
consistent copy of each database (`warden-cp.db`, `warden-alerts.db`,
`warden-fleet.db`), the served `config.yaml` and a `manifest.json` written last.
It is built in `.tmp-<time>` and renamed into place, so a set directory exists
only when complete. Directories are 0700 and files 0600. Each database copy is
consistent on its own; the set is not one snapshot across databases. The
manifest's sha256 values check integrity, not authenticity.

A set never holds `cp-audit.key` (or its HMAC key), the identity provider's
storage or the secret backend (`not_included` in the manifest). A store that is
not running (no alert store, `--analytics-provider=memory`) is listed under
`skipped`. A run needs 1.2x the source sizes free on the backup filesystem or it
fails with `insufficient free space` and writes nothing. Each copy logs
`msg=cp_backup` with `db`, `bytes`, `duration_ms` and `outcome`.

**Health.** A backup that fails or goes quiet is not silent. A failed run logs
ERROR `msg=cp_backup_failed` (`db`, error cut to 200 bytes) and publishes one
`backup_failed` Finding (severity high, dedup key `backup_failed:<db>`, where
`<db>` is the failing source or `run`). A check every max(1m, interval/4)
publishes one `backup_stale` Finding (high, dedup key `backup_stale`) when the
last success is older than twice `--backup-interval`; with no success since
start, the start time counts as the last one. A success ends the episode.
Findings carry the db name and the bounded error text, never row contents. With
no alert pipeline the Finding is logged at ERROR as `finding_not_published`.

`GET /dashboard/api/setup` gains `backup` (`enabled`, `lastSuccessAt`,
`lastError`, `lastSet`, `sizeBytes`) for an admin session, or for any caller when
`console.auth` is `none`. Viewers and editors never see it, and it is absent when
`--backup-dir` is unset. The dashboard header shows a green or red badge from it.

### On-demand backups

With `--backup-dir` set, `POST /dashboard/api/backup` (admin role, audited as
`backup.run` on target `backup`) starts one backup in the background and answers
`202 {"started":true}`. It answers `409 {"error":"backup_in_progress"}` while a
run is active and `404` when `--backup-dir` is unset. The body is ignored. In
`console.auth: none` the write guard applies as for every dashboard write (the
admin bearer; no token configured means `403`). The outcome is the scheduled
runner's: a failed run is logged and reported, not returned to the caller.

For a stopped control plane use the offline command, which takes the state-dir
lock, opens the databases directly and writes one set in the same layout:

```sh
warden control-plane backup --state-dir /data --backup-dir /backups \
  [--backup-include cp,alerts,config,fleet] [--analytics-db PATH] [--alerts-db PATH]
```

It prints the set path and exits 0, or prints the error and exits 1. While a
control plane holds the state dir it exits 1 with `control plane is running; use
POST /dashboard/api/backup or stop it`. It never opens the admin audit store (the
manifest has no `audit_key_fingerprint`), never starts a server and never prunes
older sets. A database that does not exist (for example no fleet database) is
listed under `skipped`; a missing `warden-cp.db` is an error.

## Worker tokens API

With a state dir (`--state-dir`) the control plane keeps per-worker tokens (a worker
presents `wwt_...` on `/policy`, `/control/heartbeat` and `/central/ingest`; the token's bound
proxy id is the identity the control plane records). Admins manage them under
`/dashboard/api/worker-tokens`:

| Request | Role | Result |
|---|---|---|
| `GET /dashboard/api/worker-tokens` | viewer | 200, every token (revoked included): `id`, `name`, `proxyID`, `createdBy`, `createdAt`, `expiresAt`, `lastUsedAt`, `revokedAt`. Never the token or its hash. |
| `POST /dashboard/api/worker-tokens` `{name, proxyID, expiresIn?}` | admin | 201 with the metadata and `token`, the only time the plaintext is shown (`Cache-Control: no-store`). `expiresIn` is a duration such as `720h`. 400 for invalid input or an unknown field, 409 for a taken name or a proxy id that already has two active tokens, 413 over 8 KiB. |
| `DELETE /dashboard/api/worker-tokens/{id}` | admin | 204, soft revoke: the token's next request is a 401. 404 for an unknown id. |

With `console.auth: none` a mint or revoke answers 403 `{"error":"use_cli"}` (there is no identity to
attribute it to); use `warden control-plane token` on the control plane host. Listing still works.
With admin audit on, create and revoke are rows (`worker_token.create`, `worker_token.revoke`,
target `worker_tokens`, `target_ref` `token:<id>`); no row, log line or later response holds the token.
A `wwt_` bearer never opens these routes. `GET /dashboard/api/workers` adds `authKind`
(`token`, `legacy` or `none`), `tokenName`, `tokenLastUsed` and `legacyRequests` per worker.

## Agent registry API

With a state dir (`--state-dir`) the control plane keeps a registry of agents: which agents exist,
which public keys authenticate them and which user groups may delegate to them. Rows are never
deleted and ids are never reused (an agent is switched off, not removed), so there is no `DELETE`.
Admins manage the registry under `/dashboard/api/agents`; viewers and editors may read it.

| Request | Role | Result |
|---|---|---|
| `GET /dashboard/api/agents` | viewer | 200 `{"agents":[...]}`, every agent (disabled included) ordered by id. |
| `POST /dashboard/api/agents` | admin | 201 with `Location` and `ETag: "r1"`; the body is the agent. |
| `GET /dashboard/api/agents/{id}` | viewer | 200 with `ETag: "r<revision>"`, or 404. |
| `PUT /dashboard/api/agents/{id}` | admin | 200 with the new `ETag`. Replaces `displayName`, `keys`, `allowedGroups`, `allowedScopes`; the status and the owner are kept. |
| `POST /dashboard/api/agents/{id}/disable` and `/enable` | admin | 200 with the new `ETag`. Enabling an agent with no allowed groups is 400. |

A create or edit body is one JSON object (unknown fields, including `ownerSub` and `status`, are
`400 {"error":"invalid_json"}`; over 64 KiB is 413):

```json
{"id":"claude-code","displayName":"Claude Code",
 "keys":[{"kty":"OKP","crv":"Ed25519","x":"<32-byte base64url>"}],
 "allowedGroups":["warden-agents"],"allowedScopes":["read"]}
```

`keys` holds 1 or 2 public JWKs (two during a rotation): `OKP`/`Ed25519` or `EC`/`P-256`; a private
member (`d`, `p`, ...) or a member that makes a verifier fetch something (`jku`, `x5u`, `x5c`) is
refused. `id` matches `^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$` and is the path's id on a `PUT`.
`allowedGroups` are normalized like policy rule groups and an active agent needs at least one.
The owner (`ownerIss`, `ownerSub`, `ownerEmail`) is the signed-in admin who registered the agent;
it is informational and never an authorization input.

The agent view, the same in every response:

```json
{"id":"claude-code","displayName":"Claude Code","ownerIss":"https://idp.example","ownerSub":"u1",
 "ownerEmail":"ada@example.com",
 "keys":[{"kid":"<jkt>","alg":"EdDSA","jkt":"<jkt>","jwk":{"kty":"OKP","crv":"Ed25519","x":"...","kid":"<jkt>","alg":"EdDSA","use":"sig"}}],
 "allowedGroups":["warden-agents"],"allowedScopes":[],"status":"active","revision":1,
 "createdAt":"2026-01-01T00:00:00Z","createdBy":"oidc:u1","updatedAt":"2026-01-01T00:00:00Z","updatedBy":"oidc:u1"}
```

`kid` is the key id the agent puts in its JWT header (the key's own `kid` member, else the RFC 7638
thumbprint `jkt`); `jkt` is unique across the whole registry, so a key authenticates exactly one
agent. Views carry public JWKs only. Responses are `Cache-Control: no-store`.

`PUT`, `disable` and `enable` need `If-Match: "r<revision>"`, the value of the `ETag` of a read.
Missing is `428 {"error":"if_match_required"}`, malformed (there is no `*`) is
`400 {"error":"invalid_if_match"}`, and a revision that is no longer the stored one is
`409 {"error":"agent_conflict"}`: re-read and retry. Every successful edit and status change
increments the revision.

| Status and body | Meaning |
|---|---|
| 400 `{"error":"invalid_agent","field":"keys[0].crv","message":"..."}` | A validation failure; `field` names the member in the API's names (`displayName`, `keys[1].jwk`, `allowedGroups[0]`), `message` is a fixed phrase. The submitted value is never echoed. |
| 404 `{"error":"not_found"}` | No agent has the id. |
| 409 `{"error":"agent_exists"}` / `{"error":"key_in_use"}` / `{"error":"agent_conflict"}` | The id is registered, a key is bound to another agent, or the `If-Match` revision is stale. |
| 422 `{"error":"registry_full"}` | The registry holds the maximum of 1000 agents. |
| 403 `{"error":"use_cli"}` | Writes with `console.auth: none`. |
| 503 `{"error":"state_dir_required"}` | The control plane has no `--state-dir`; every route answers it. |
| 404 | A worker's dashboard: it never serves the routes. |

With `console.auth: none` there is no identity to attribute a key or group change to, so a write
answers `403 use_cli` even with the admin bearer; reads still work. In oidc mode a viewer or editor
write is `403 role_required`. With admin audit on, each successful write is one row
(`agent.create`, `agent.update`, `agent.disable`, `agent.enable`; target `agents`, `target_ref`
`agent:<id>`). A refused or failed write is a row too (`denied`, `rejected` or `error`). The row
details name what changed, never key material, and use these keys only: `op` (`create`,
`update`, `disable` or `enable`), `changed` (an update's edited fields: `displayName`, `keys`,
`allowedGroups`, `allowedScopes`, `status`), `kidsAdded` and `kidsRemoved` (key ids), `jktsAdded`
and `jktsRemoved` (full RFC 7638 thumbprints, so swapping key material under one kid is visible),
`groupsAdded` and `groupsRemoved`, `statusFrom` (only when there was a previous row) and `statusTo`.
A list holds its elements sorted by raw value, each percent-encoded (every byte outside
`A-Za-z0-9-._~:` becomes `%XX` in uppercase hex, `%` and `,` included) and joined with `,`.
A create and an update always carry a `<list>Count` (the full number of elements, for example
`groupsAddedCount`) for each of the six lists; a disable or enable carries no list. A list that
would not fit one 256-byte value is cut at an element, and only then the row also carries
`truncated: "true"` and `<list>Sha256`: the lowercase hex sha256 of the full list in the canonical
form above (elements sorted by raw byte value before encoding, then encoded, then joined with
`,`), so a padded list cannot hide an addition. Empty values are omitted. No JWK coordinate appears
in an audit row, a log line or an error. The control plane
also keeps in-memory counters for retention reporting: `warden_cp_agent_registry_writes_total{action,outcome}`
and `warden_cp_agents{status}`.

A write by another process (the offline registry CLI) is seen by the control plane within about
2 seconds.

## Operating the agent registry

The [API above](#agent-registry-api) is how agents are written; this section is how the registry
behaves once workers depend on it.

**What the registry holds.** Per agent: the id, a display name, one or two public keys, the user
groups that may delegate to it, the scopes a delegation may carry, a status (`active` or
`disabled`) and a revision. An id matches `^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$` and is never
reused. A key is an `OKP`/`Ed25519` or `EC`/`P-256` public JWK; a private member, `jku`, `x5u`
and `x5c` are refused. The registry holds at most 1000 agents. It does **not** hold the agent's
identity mode: that stays in the settings field `agents[].identity` (and `identity.defaultMode`),
so there is one source of truth for it and a registry write never changes how strictly a worker
enforces identity.

**Who may write it.** Every write is admin-only, because a key or group change decides who can
mint tokens for the agent, and `PUT`, `disable` and `enable` need `If-Match: "r<revision>"`.
The identity mode is admin-only as well: an editor may edit `agents` in the settings but not
`agents[].identity` (see the [role matrix](#console-roles-and-the-role-matrix)). With
`console.auth: none` a write through the API is `403 use_cli`; manage the registry with the
offline CLI. With approvals on, registering an agent, adding a group, scope or key, and enabling
an agent are held as `agents` change drafts, while disabling one and edits that only narrow apply
at once (see [Change drafts](#change-drafts-and-the-two-person-rule-consoleapprovals)). The
offline CLI is not held.

### The offline CLI

The CLI writes `<state-dir>/warden-cp.db` directly, with the control plane running or stopped; a
running control plane serves the change within about 2 seconds. Only public keys are accepted, and
output never includes a JWK coordinate. Each write is a `cli:<os user>` row in the admin audit
log when admin audit is enabled.

```sh
warden control-plane agent register --state-dir /var/lib/warden-cp --id claude-code \
  --display-name "Claude Code" --groups warden-agents --jwk-file claude-code.jwk.json
warden control-plane agent list --state-dir /var/lib/warden-cp
warden control-plane agent disable --state-dir /var/lib/warden-cp --id claude-code --revision 1
warden control-plane agent enable --state-dir /var/lib/warden-cp --id claude-code --revision 2
```

`--revision` is the revision `agent list` shows; a stale one changes nothing and exits 1. Exit
codes: 0 done, 1 refused with nothing changed (validation, conflict, key in use, unknown id),
2 usage.

### Rotating an agent's key

An agent holds one or two keys, so a key is replaced without a gap. `agent update` replaces the
agent's whole key set with the `--jwk-file` values it is given:

1. Update to both keys (old and new) and restart the agent with the new private key. Both
   thumbprints are accepted while the two are registered.
2. Wait at least one Warden token lifetime (`tokenService.ttl`, default 15 minutes) plus the
   clock skew after the agent last minted a token with the old key, then update to the new key
   alone.

```sh
warden control-plane agent update --state-dir /var/lib/warden-cp --id claude-code --revision 3 \
  --jwk-file claude-code-old.jwk.json --jwk-file claude-code-new.jwk.json
```

With approvals on, adding the new key through the API is held as an `agents` change draft, while
removing the old one applies at once (the offline CLI is never held).

Removing a key is not only a registry edit. A Warden token carries the thumbprint of the key it
was minted for (`cnf.jkt`); once a worker applies the policy that no longer lists it, that token
fails with `cnf_mismatch` and the worker closes the identified sessions that were opened under it.
Keep both keys registered until the agent has switched, and allow one policy-wire cycle after the
final update. (This is the agent's key; the control plane's own signing keys rotate with
[`keys rotate`](#signing-keys-keys).)

### Binding a worker to an agent

A worker serves exactly one agent. It takes the id from the first of these that is set:

1. `--agent-id` on `warden run`;
2. `central.agentID` in the worker config;
3. the derived default (`defaultAgentID`): the id of the one configured agent policy when there is
   exactly one, else `agent:<port>` from the listen port.

An explicit id (1 or 2) that is not a valid agent id stops the worker at startup. The derived id
is used as it is and is never validated; it matches a registry entry only when the two ids are
identical (`agent:8080` is a valid id shape, so it could be registered, but nobody does by
accident). Name the worker explicitly with `--agent-id` or `central.agentID` so the registry
governs it by design rather than by coincidence. The worker reports
the id and its identity mode on every heartbeat so the Agents tab can join them with the registry.

### The kill switch

On every applied policy the worker finds its own agent in `registeredAgents` (id, status and key
thumbprints, served on the `/policy` long-poll and inside signed bundles). While that agent is
`disabled`, in **every** identity mode including `off`, the worker:

- refuses each new CONNECT, request and HTTP/2 stream with `403 {"error":"agent_disabled"}`,
  ahead of identity, the block list and policy, so nothing reaches a judge, a secret swap or an
  upstream;
- closes every open tunnel, keep-alive or HTTP/2 connection and WebSocket, and writes one
  `agent_disabled` deny event for each (a request already in flight completes);
- lifts all of it on the next applied policy after the agent is enabled again.

An agent with no registry entry is not disabled: an unregistered id is not a registry agent (its
Warden tokens fail the binding check with `agent_unregistered` instead). A disabled agent also
cannot get a token: the token endpoint answers it `invalid_client`, the same as an unknown agent.

### What survives what

| Event | Effect on a disabled agent |
|---|---|
| A policy rollback or any settings save | None. The registry is overlaid on the served policy and is never part of a policy version, so a rollback can neither re-enable an agent nor restore a removed key. |
| The control plane is down | Workers keep enforcing the last-known-good policy, so a disabled agent stays disabled. A worker that restarts during the outage uses its cached bundle only with the opt-in [last-known-good cache](#last-known-good-bundle-cache-opt-in) (`controlPlane.stateDir` with pinned bundle keys, and a bundle issued within `controlPlane.bundleCacheMaxAge`); otherwise it denies all until its first pull. |
| The registry cannot be read | The control plane logs `agentreg_load_failed` once per failure episode (it logs again after a successful read and a later failure) and keeps serving the last-known-good list. |
| A bundle is rejected (bad signature, expired) | The worker keeps its last-known-good bundle, so the agent stays in the state that bundle had. |
| An old worker without the `agentreg/v1` capability | It decodes the list and ignores it: **it does not enforce disable.** The Agents tab warns that the disabled agent is still served by workers without `agentreg/v1`. Upgrade it before relying on the switch. |

A disable reaches a worker within one policy long-poll: the control plane serves it within a few
seconds of the write and the worker applies it at once.

### Require mode and the registry

Identity `require` mode (settings `agents[].identity: require`) is what makes the registry
mandatory: every request must carry a Warden token bound to the worker's agent. The guard on the
switch to `require` (a connected worker without `identity/require-v1` blocks it unless an admin
forces it) is in [Moving an agent from attribute to require](#moving-an-agent-from-attribute-to-require).
It is advisory outside token or certificate worker auth, because the agent id a worker reports is
self-asserted. When an agent is disabled or a key removed, the identified sessions armed under the
old binding are closed after the next applied policy; see
[Agent binding of Warden tokens](identity-contract.md#agent-binding-of-warden-tokens).

### The Agents tab

With a state dir the console has an **Agents** tab: the registry list, an admin form to register,
edit, disable and enable (writes send `If-Match`, a private JWK is refused in the browser, and only
public JWKs are shown), and each agent's bound workers from the heartbeat. Warnings name a disabled
agent still served by a worker without `agentreg/v1`, an active agent no worker serves, a worker
reporting an unregistered agent id, and workers that cannot enforce `require`. The tab is hidden on
a control plane without a state dir.

## Worker token CLI

`warden control-plane token` creates, lists and revokes worker tokens straight on
`<state-dir>/warden-cp.db`, with the control plane running or stopped. It needs no admin login, so it
bootstraps the first tokens, and it is the only way to mint or revoke with `console.auth: none`. A
running control plane sees a change within about 2 seconds, with no restart. Every subcommand
takes a required `--state-dir`.

```sh
# Mint a token: the plaintext is printed once to stdout (the id and a note go to stderr).
warden control-plane token create --name worker-2 --proxy-id worker-2 --state-dir /var/lib/warden-cp

# Write it to a new file (mode 0600) instead; only the id is printed.
warden control-plane token create --name worker-2 --proxy-id worker-2 --state-dir D --out worker-2.token

# Register a value you generated (a wwt_ token, 4 + 52 characters), for compose or Kubernetes Secrets.
WARDEN_WORKER_1_TOKEN=wwt_... warden control-plane token create --name worker-1 --proxy-id worker-1 \
  --from-env WARDEN_WORKER_1_TOKEN --state-dir D

warden control-plane token list --state-dir D [--json]
warden control-plane token revoke --id wt_... --state-dir D
```

| Flag (create) | Meaning |
|---|---|
| `--name`, `--proxy-id` | required; the name is unique (1-64 characters), the token is bound to exactly one proxy id |
| `--expires-in` | lifetime such as `720h`; default never |
| `--from-env VAR`, `--from-file F` | register the `wwt_` value instead of minting one; the plaintext is never printed. Re-running with the same name and value changes nothing and exits 0; the same name with a different value fails |
| `--out F` | write a minted token to the new file `F` (mode 0600); an existing file is never overwritten |
| `--admin-audit-key-file` | admin audit signing key (default `<state-dir>/cp-audit.key`) |

At most two tokens per proxy id may be active, so a rotation can overlap old and new. Exit codes: 1
for any failure (invalid input, a taken name, a bad key), 2 for `revoke` of an unknown id.
`list` opens the database read-only and never shows a token or its hash.

When admin audit is on in the state dir, `create` and `revoke` append `worker_token.create` and
`worker_token.revoke` rows (target `worker_tokens`, `target_ref` `token:<id>`, `auth_method` `cli`,
actor `cli:<os user>`, details holding the id, name and proxy id only). With audit rows present and
the signing key missing or not matching, the command exits non-zero and writes nothing. When audit
was never enabled, a one-line notice says no row was appended. A no-op (an identical import, a
repeat revoke) appends nothing.

## Migrating from WARDEN_CP_TOKEN

Until now every worker and the control plane shared one bearer token (`WARDEN_CP_TOKEN` in the
compose recipes, named by `--token-env`). Per-worker tokens replace it: one revocable `wwt_...`
token per worker, bound to one proxy id. The e2e stack and the compose recipes other than
`docker-compose.control-plane.yml` run on them; the control-plane recipe has moved on to
[worker certificates](#migrating-from-per-worker-tokens) (see [Run it](#run-it)).
The control plane has four auth modes, resolved once at
startup and logged as `auth_mode=...`:

| `auth_mode` | When | Workers authenticate with |
|---|---|---|
| `open` | no shared token, not strict | any caller without a `wwt_` token (development; a warning is logged). A `wwt_` bearer is always validated |
| `mixed` | `--legacy-token-env` set (or its deprecated alias `--token-env`) | a worker token or the shared token |
| `strict` | `--require-worker-tokens` | a worker token only: the shared token and anonymous callers get `401` |
| `strict-certs` | `--require-worker-certs` | a worker certificate only (workerCA): tokens, the shared token and anonymous callers get `401` |

The startup line `control plane worker auth` also carries `legacy_token` (whether a shared token is
configured, never its value), `tls` and `active_worker_tokens`. Worker tokens over plain HTTP log a
warning, since the bearer then travels in clear text.

The flags only change how **workers** authenticate. Dashboard writes and `/central/secrets` take
the control plane's own admin bearer (`--admin-token-env`), so removing the shared token never
disables them. The shared token reaches the write guard only as the fallback while
`--admin-token-env` is unset.

| Flag | Meaning |
|---|---|
| `--legacy-token-env <ENV>` | env var holding the shared worker token. Unset (the default) means there is none. `--token-env` is a deprecated alias: it still works and logs a deprecation notice; naming two different variables with the two flags is a startup error. |
| `--require-worker-tokens` | strict mode (default off). Needs `--state-dir` (tokens live in its database), TLS (`--ca-cert` and `--ca-key`) unless `--allow-insecure-worker-auth` is set, and no legacy token. |
| `--require-worker-certs` | strict-certs mode (default off). Needs `workerCA.enabled`, `--state-dir` and TLS, and neither `--require-worker-tokens` nor a legacy token. See "Worker certificate authentication". |
| `--allow-insecure-worker-auth` | lets `--require-worker-tokens` run without TLS (development only). |

A violation exits non-zero before the control plane listens, with an error that names the flag
(`--require-worker-tokens requires --state-dir`, `--require-worker-tokens cannot be combined with
--legacy-token-env`, `--require-worker-tokens requires TLS (--ca-cert and --ca-key) or
--allow-insecure-worker-auth`).

### Migration steps

1. **Upgrade with `--legacy-token-env` and set `--admin-token-env`.** Rename `--token-env` to
   `--legacy-token-env` (the old name keeps working) and add `--admin-token-env
   WARDEN_CP_ADMIN_TOKEN` with a value different from the shared token, so dashboard writes no
   longer depend on it. Add `--state-dir` if the control plane has none. The control plane starts
   in `mixed` mode: nothing changes for the workers.
2. **Create one token per worker.** Use `POST /dashboard/api/worker-tokens` (see [Worker tokens
   API](#worker-tokens-api)) with `{"name": "...", "proxyID": "..."}`. The plaintext is shown once
   in the response and never again. Minting through the API needs `console.auth: oidc` and an admin session; with
   `console.auth: none` the API answers `403 use_cli`. Use the offline `warden control-plane token
   create` command instead (see [Worker token CLI](#worker-token-cli)), which needs no login and
   works before the first start. Give every worker (or replica) its own token and its own
   `proxyID`.
3. **Point the worker at its token.** Put the token in an env var of the worker and name that var
   in both `controlPlane.tokenEnv` and `central.tokenEnv` (policy pull and heartbeat use the first,
   analytics ingest the second). Set `central.proxyID` to the same value the token is bound to:
   the control plane answers `403 proxy id mismatch` for any other `X-Warden-Proxy-ID`. Without
   `central.proxyID` the worker sends no id and the control plane records the token's bound id.
   Restart the worker. No code or image change is needed.
4. **Confirm no legacy badge.** `GET /dashboard/api/workers` shows `authKind` per worker (`token`,
   `legacy` or `none`) and, for `legacy` workers, `legacyRequests`. While any worker still
   presents the shared token the control plane logs `legacy worker token in use` once per proxy id
   per hour (never the token). The control plane has no metrics endpoint in P1, so the fleet view and
   this warning are the signals. Move on only when every worker shows `authKind: token`.
5. **Restart with `--require-worker-tokens`** and without `--legacy-token-env`. The startup line now
   says `auth_mode=strict`. The shared token, an anonymous caller or any non-`wwt_` bearer gets
   `401` on `/policy`, `/control/heartbeat` and `/central/ingest`.
6. **Unset the shared env var** (`WARDEN_CP_TOKEN`) everywhere it was distributed.

Strict mode with `console.auth: none` and no `--admin-token-env` (and so no admin token at all)
fails closed: dashboard writes are refused with `403`, `/central/secrets` is not mounted (`404`),
and the control plane logs an ERROR, `dashboard writes are disabled: set --admin-token-env`. With
`--admin-token-env` set, both keep working. In `console.auth: oidc` sessions replace the admin
bearer and strict mode needs no admin token.

### Rotation

A proxy id can hold at most two active tokens at once, so a rotation overlaps old and new:

1. Create a second token for the same `proxyID` (a third active one is refused with `409`).
2. Restart the worker with the new token in its env var.
3. Check the old token's `lastUsedAt` stops moving, then revoke it
   (`DELETE /dashboard/api/worker-tokens/{id}`).

### Compromised-token runbook

A worker token is suspected leaked (a log, a ticket, a laptop, a container image). The aim is to
stop the token working at once and give the worker a new one, with the worker never running open.

1. **Revoke the token.** From the console, `DELETE /dashboard/api/worker-tokens/{id}` (an admin
   session; `GET /dashboard/api/worker-tokens` lists the ids), or on the host that holds the state
   volume, `warden control-plane token revoke --id wt_... --state-dir <dir>`. The control plane sees
   the revocation within about 2 seconds, with no restart.
2. **Watch the worker fail.** Its next `/policy` and `/control/heartbeat` calls get `401`, and
   ingest stops. The worker keeps enforcing the last-known-good policy it pulled, which is still
   default-deny, but receives no updates, and the fleet view shows it offline. A worker that
   restarts while revoked boots fail-closed and denies all egress until a pull succeeds.
3. **Re-bootstrap a replacement.** Mint a new token for the same proxy id with `warden control-plane
   token create --name <new-name> --proxy-id <id> --state-dir <dir>` (or `--from-env` with a value
   you generated), put it in the worker's env var and restart the worker. At most 2 tokens may be
   active per proxy id, so a replacement can be created before the old one is revoked: step 3 may
   come before step 1 when the worker must keep updating, at the cost of a longer exposure.
   Token names are unique and a revoked name stays taken. In the compose recipe, generate a new
   value, set `WARDEN_WORKER_N_TOKEN` to it, give that worker a new `--name` in the `cp-bootstrap`
   command (for example `w1-2`), then run `docker compose up -d`: `cp-bootstrap` registers the new
   token and recreates the worker with it. Reusing the old name with a new value makes
   `cp-bootstrap` fail, by design.
4. **Look for misuse.** In `GET /dashboard/api/workers` and the console fleet view, `tokenLastUsed`
   per worker (the token's `last_used_at`) shows when a token was last presented. Use at an
   unexpected time, or after the worker was stopped, means someone else holds the token. Check it
   before revoking (to see whether it is being used) and after (it must stop moving).

### One token per replica

P1 has no prefix binding: a token is bound to exactly one proxy id, compared exactly. Run each
replica with its own token and its own stable `central.proxyID`. Autoscaled pools whose replicas
cannot carry a stable id use a prefix-bound enrollment token with worker certificates
(W-P2-WCA): see [Replica pools](#replica-pools-prefix-tokens).

### A revoked worker

A revoked (or expired) token gets `401` on its next request, with the same generic body as any
other bad credential. The worker keeps enforcing the last policy it pulled, which stays
default-deny (anything not on that allowlist is still blocked), and it can no longer heartbeat or
ingest, so the fleet view shows it offline. A worker that restarts while revoked boots fail-closed
and denies all egress until a pull succeeds. A long-poll already held when the token is revoked is
answered `401` as soon as the control plane sees the revocation (at once for a console revoke,
within about 2 seconds for the CLI), and a held poll is re-authenticated before it is answered, so
it never receives a policy after the revoke.

## Signing keys (`keys:`)

The control plane can own the signing keys it uses for Warden tokens and policy
bundles, and store the worker CA key. The subsystem is **off by default**: with
`keys.enabled: false` (or no `keys:` block) no key directory, `signing_keys`
table or goroutine exists and the control plane is unchanged. The block is
control-plane-local — read from `--config` only, never served to workers.

```yaml
keys:
  enabled: true            # needs --state-dir
  store:
    backend: file          # file (default) or aws
    file:
      dir: ""              # default <state-dir>/keys; may be a separate secret mount
    aws:                   # with store.backend: aws only
      region: eu-central-1
      namePrefix: warden-cp-keys/   # the default; must stay disjoint from secretStore.aws.namePrefix
  token:                   # EdDSA (default) or ES256
    rotationInterval: 720h # 0 = rotate only by hand; else >= prepublish+overlap
    prepublish: 1h         # min 10m: a next key is published before it activates
    overlap: 48h           # min 20m: a retired key stays in the JWKS this long
  bundle:                  # must be EdDSA: workers pin bundle keys
    rotationInterval: 0    # must be 0: bundle rotates only by hand
    prepublish: 1h
    overlap: 48h
```

- **Where keys live.** Private keys are PKCS#8 PEM files at
  `<dir>/<purpose>/<kid>.pem` (directories 0700, files 0600, created exclusively
  and fsynced). `warden-cp.db` holds only public metadata (the `signing_keys`
  table: kid, purpose, algorithm, state, public JWK, timestamps). The kid is the
  RFC 7638 thumbprint of the public key.
- **First start.** For each of `token` and `bundle` with no rows the control
  plane creates an active key and a next key, writes a `keys.generated` admin
  audit entry for each (when admin audit is on) and logs `keys_loaded`. A restart
  keeps the same kids. The `ca` purpose is never generated: it is filled by
  importing the worker CA key.
- **Store unavailable.** If rows exist but the active key cannot be read, the
  control plane starts anyway: `/policy` and `/healthz` keep serving, `/readyz`
  answers 503 and `/.well-known/jwks.json` answers 503 `signing_unavailable`
  until a key loads, signing returns `ErrNoActiveKey`, a `signing_key_unavailable` finding is raised once
  per outage, and loading is retried with 1 s to 60 s backoff until it works. It
  never generates a replacement key while rows exist.
- **Rotation.** Token keys rotate on `rotationInterval` (default 720 h;
  `0` rotates only by hand). Bundle keys must be `rotationInterval: 0`, because
  workers pin them out of band — rotating a bundle key is a staged operator
  action. A rotation promotes the published next key to active (never before
  `publish_at + prepublish`, so verifiers already hold it), retires the old key
  — whose private material is deleted at once — and publishes a fresh next key.
  The retired key stays in the JWKS for `overlap` (default 48 h, min 20 m), so
  tokens it signed keep verifying, and its row is then destroyed. Every
  transition is a compare-and-swap write, so the scheduler, the console and the
  CLI cannot fork the lifecycle, and a restart applies the transitions a
  downtime made due. A rotation that fails keeps the current key and raises
  `key_rotation_failed`; an active token key older than twice its interval
  raises `key_overdue`.
- **Token JWKS.** `GET /.well-known/jwks.json` (GET and HEAD only; other methods
  405) is public: it sits outside sessions, the role table, the admin audit and
  worker auth, and exists only with `keys.enabled` (else 404). It serves
  `{"keys":[...]}` with the token purpose's next, active and in-overlap retired
  keys, members `kty`, `crv`, `x`, `y`, `kid`, `alg`, `use` only (bundle keys are
  never served here). The bytes are built from the in-memory key set, so a request
  does no store or database I/O. Headers: `Content-Type: application/jwk-set+json`,
  `Cache-Control: public, max-age=300`, and an `ETag` that is the quoted base64url
  sha256 of the body; a matching `If-None-Match` gets 304. With no published token
  key it answers 503 `{"error":"signing_unavailable"}` with `Cache-Control: no-store`.
- **Readiness.** `GET /readyz` is 200, or 503 `{"keys":"no_active_key"}` when keys
  are enabled and any purpose has no loaded active key. `/healthz` stays plain
  liveness and is unaffected, so a key outage does not restart the process.
- **Admin key API.** `GET /dashboard/api/keys` (admin) lists each key's kid,
  purpose, algorithm, state, timestamps, backend and public JWK, and per purpose
  whether a key is loaded and the last load error; it never returns private
  material. `POST /dashboard/api/keys/rotate` (admin, CSRF, audited as
  `keys.rotate_requested`, target ref `keys:<purpose>`) takes
  `{"purpose":"token","emergency":false}`. It answers 403 `use_cli` under
  `console.auth: none` (there is no identity to attribute the rotation to) and 409
  `use_cli` for the `bundle` purpose (its rotation is staged on the host); both
  point at `warden control-plane keys rotate`. A next key not yet published long
  enough, or a lost race, is 409. Both routes are 404 without `keys.enabled`.
- **Orphans.** At startup, key files with no `signing_keys` row (a crash between
  writing the file and the insert) are deleted; the log names the kid and
  purpose only.
- **Backups.** The P1 backup set holds the database (public metadata) but not
  the key directory (the manifest lists it under `not_included`). Back the
  directory up separately, or restoring will leave rows without material; the
  restore says which purposes are missing material and prints the reset hint.
  With `store.backend: aws` there is no key directory: the manifest names none,
  the material lives in AWS Secrets Manager under the keys prefix, and a
  restored database re-resolves against it. Rotation procedures, the staged
  bundle rollout and the emergency drill are in
  the [key rotation runbook](runbooks/key-rotation.md).

### Keys CLI

`warden control-plane keys` lists, rotates, exports and resets signing keys
straight on the state dir, with the control plane running or stopped. A running
control plane sees a rotation within about 2 seconds, with no restart. `reset`
refuses while the control plane holds the state-dir lock. Every subcommand
takes a required `--state-dir` and an optional `--config` naming the file with
the `keys:` block. With `store.backend: aws` the CLI builds the same Secrets
Manager store the control plane does — region and prefix from that config's
`keys.store.aws`, credentials from the environment or instance role — so run it
where the control plane's role is; `reset` deletes the old secrets from the
account.

```sh
warden control-plane keys list --state-dir /var/lib/warden-cp [--purpose token] [--jwks] [--json]
warden control-plane keys rotate --purpose token --state-dir /var/lib/warden-cp [--config F] \
  [--emergency --yes]
warden control-plane keys rotate --purpose bundle --stage --state-dir /var/lib/warden-cp
warden control-plane keys rotate --purpose bundle --activate --state-dir /var/lib/warden-cp \
  --admin-url https://cp.example.internal:7070 --api-key-file rotate.key [--force]
warden control-plane keys export --purpose bundle --state-dir /var/lib/warden-cp [--state next]
warden control-plane keys reset --purpose token --yes --state-dir /var/lib/warden-cp
```

- **list** prints one row per key (kid, purpose, state, algorithm, timestamps,
  creator) — public metadata only; `--jwks` prints the published key set
  instead. The export path prints public JWKs only, never a `d` member or a
  PEM block.
- **rotate** promotes `next` to active, retires (or, with `--emergency`,
  revokes) the old active — deleting its private material at once — and
  publishes a fresh `next`. It refuses while the `next` key is younger than
  `prepublish`, and `--emergency` requires `--yes` on a non-interactive stdin.
  An emergency whose revocation committed but whose fresh `next` could not be
  written still stands: the command exits **3** and says the old key is
  revoked — the error names only the missing `next` — and its audit row has
  outcome `error`. The `bundle` purpose rotates only in two steps, because workers
  pin its keys: `--stage` makes the control plane sign every envelope with both
  the active and the next key (a worker pinning either verifies it), and
  `--activate` makes the next key the only signer, keeping the old one published
  for `keys.bundle.overlap`. `--activate` is refused, naming the proxy ids,
  unless every online worker reports the next kid in its heartbeat `pinnedKids`;
  it reads them from the running control plane (`--admin-url` and an API key with
  the `traffic:read` scope in `--api-key-file` or `$WARDEN_API_KEY`) and refuses
  when it cannot. `--force` overrides the check and records the missing ids in
  the one audit row it writes; `--activate --emergency --yes` promotes at once
  and revokes the old key; `--unstage` takes the staged key back out of signing and
  is the recovery when its material is lost (`/readyz` then answers
  `staged_key_unavailable`). `--admin-url` must be https (http only for loopback). Without a step the bundle purpose is refused and the
  `next` kid to pin is named. The scheduler never rotates the bundle purpose
  (`keys.bundle.rotationInterval` must be `0`). The whole flow, the emergency
  drill and the restore step are in
  [the key rotation runbook](runbooks/key-rotation.md#6-staged-bundle-rotation).
- **export** prints one key's public JWK (`--state next` or `active`) or, by
  default, the published JWKS (active, next, and a retired key inside its
  overlap) — the exact document a worker pins in `controlPlane.bundleKeysFile`.
  It never prints private material.
- **reset** deletes every key of the purpose (rows and PEM files) and
  regenerates `token`/`bundle`; `--purpose ca` only clears, the CA key is
  imported, not generated. It needs `--yes`.

When admin audit is on in the state dir, `rotate` and `reset` append one row
(`keys.rotate_requested`, `keys.reset`; `auth_method` `cli`, actor
`cli:<os user>`; a bundle `--stage` or `--activate` carries `op=stage` or
`op=activate`, and a forced activation `forced=true` with the missing proxy ids) and the transitions the request causes carry the same actor.
With no audit table a log line names the action instead; with rows present and
the audit key missing or mismatched the command refuses and changes nothing.

Exit codes:

| Code | Meaning |
|---|---|
| 0 | Applied. |
| 1 | Nothing changed — a refusal: no or too-young `next` key, a bundle rotation without `--stage` or `--activate`, an `--activate` the pin check refused, or `reset` under the running control plane's state-dir lock. A reset that partially applied also exits 1: its rows are gone and its audit row has outcome `error` with the removed count. |
| 2 | Usage error: a bad flag, a missing or unopenable state dir or audit key, a missing `--yes` or a declined confirmation, or `rotate --purpose ca`. |
| 3 | A stood rotation: the promotion committed, so the old key is out of the signing slot — revoked under `--emergency`, retired otherwise — and only the fresh `next` key is missing. |

Key material never appears in the database, logs, errors or audit entries.

### AWS Secrets Manager backend (`store.backend: aws`)

With `store.backend: aws` the private keys live in AWS Secrets Manager, one
secret per key at `<namePrefix><purpose>/<kid>` (default prefix
`warden-cp-keys/`), the PKCS#8 PEM as the secret value. Everything else behaves
like the file store: a generation is written, read back and compared before its
row is inserted; a restart loads the same kids; the startup sweep deletes
secrets with no row; deleting a key deletes its secret at once.

- **Credentials.** The control plane resolves credentials from its own
  environment or instance role (explicit → env → IMDS) — never from config:
  the `keys.store.aws` block has only `region` and `namePrefix`, and the strict
  YAML parser rejects a credential field there.
- **Isolation from workers.** Workers reach Secrets Manager only through their
  own `secretStore.aws` block — their own region, prefix and role. Startup
  fails when `keys.store.aws.namePrefix` equals, starts with, or is a prefix of
  `secretStore.aws.namePrefix` (or the reverse), naming both fields: a worker
  scoped to the secretStore namespace must not be able to name a key secret.
  The defaults (`warden-cp-keys/` and `warden/`) are disjoint. The startup log
  names the region and prefix only — values and credentials are never logged.
- **Backups, restore and the CLI.** A backup set still never contains the key
  material — Secrets Manager values are not in it any more than PEM files are
  (`not_included` names signing key material either way). A restore of rows
  that record the aws backend claims no key directory and reports nothing
  missing; it prints a note that the material lives in AWS Secrets Manager
  under the keys prefix, and the operator verifies the control plane can read
  it at the next start. `warden control-plane keys` drives the same backend:
  rotate, export and reset read and delete Secrets Manager values with the
  credentials of the environment the command runs in — run it where the control
  plane's role is.
- **IAM.** Give the control plane's role rights on the CP prefix only.
  `ListSecrets` needs its own statement: AWS does not support resource-level
  permissions for it (scoping it to the prefixed ARN makes every list fail with
  `AccessDenied` and breaks the orphan sweep). It is account-wide by design but
  carries secret **names only, never values**, and the client sends the
  name-prefix filter (`Filters: [{Key: "name", Values: ["warden-cp-keys/"]}]`)
  and filters the response again itself, so the sweep sees only the CP
  namespace:

  ```json
  {
    "Version": "2012-10-17",
    "Statement": [
      {
        "Sid": "WardenControlPlaneKeys",
        "Effect": "Allow",
        "Action": [
          "secretsmanager:CreateSecret",
          "secretsmanager:PutSecretValue",
          "secretsmanager:GetSecretValue",
          "secretsmanager:DeleteSecret"
        ],
        "Resource": "arn:aws:secretsmanager:*:ACCOUNT_ID:secret:warden-cp-keys/*"
      },
      {
        "Sid": "WardenControlPlaneKeyList",
        "Effect": "Allow",
        "Action": "secretsmanager:ListSecrets",
        "Resource": "*"
      }
    ]
  }
  ```

  A worker role keeps the same shape over its own prefix and **cannot read** the
  keys namespace — the deny is structural (the value actions name no
  `warden-cp-keys/*` resource), and an explicit Deny makes it hold even if a
  later `warden/*` grant is widened. `ListSecrets` is again a `Resource: "*"`
  statement of its own; it can surface key secret *names* to the account, but
  no value is reachable without `GetSecretValue`, which the Deny withholds for
  every read/write action on the keys prefix:

  ```json
  {
    "Version": "2012-10-17",
    "Statement": [
      {
        "Sid": "WardenWorkerSecrets",
        "Effect": "Allow",
        "Action": "secretsmanager:GetSecretValue",
        "Resource": "arn:aws:secretsmanager:*:ACCOUNT_ID:secret:warden/*"
      },
      {
        "Sid": "WardenWorkerSecretList",
        "Effect": "Allow",
        "Action": "secretsmanager:ListSecrets",
        "Resource": "*"
      },
      {
        "Sid": "NeverTheControlPlaneKeys",
        "Effect": "Deny",
        "Action": [
          "secretsmanager:GetSecretValue",
          "secretsmanager:PutSecretValue",
          "secretsmanager:CreateSecret",
          "secretsmanager:DeleteSecret",
          "secretsmanager:UpdateSecret",
          "secretsmanager:RestoreSecret",
          "secretsmanager:TagResource",
          "secretsmanager:PutResourcePolicy"
        ],
        "Resource": "arn:aws:secretsmanager:*:ACCOUNT_ID:secret:warden-cp-keys/*"
      }
    ]
  }
  ```

### Reserved `cp/` secret namespace

The logical key `cp` and every key under `cp/` are reserved for control-plane
material (the worker CA keeps its material there). The signing keys and the
worker CA key live in the separate key store above, which no placeholder can
reach; reserving `cp/` in the shared secret store is defense in depth, so
nothing control-plane only can ever sit where a worker or a human route could
reach it. The rule is unconditional and applies to every backend:

- A worker refuses a `cp/` placeholder with `ErrReservedKey` before it calls the
  backend, and the request is denied like any placeholder that cannot be
  resolved.
- Config validation rejects a `secrets[]` placeholder, or an `auth[]` credential
  field, that names `cp/`. The error names the entry and the field, never the
  value.
- `GET /central/secrets` and `GET /dashboard/api/secretstore` leave `cp/` keys
  out. `POST` and `DELETE` on a `cp/` key (on `/central/secrets` and on
  `/dashboard/api/secretstore`) return `403` with `{"error":"reserved_key"}`
  and never reach the store. The attempt is recorded as a denied admin-audit
  row that does not name the key.
- A refused attempt logs `reserved secret key refused` with the route (or
  `worker-cache`) and the key prefix `cp/` only, at most once a minute per
  source.

The reserved names are `<secretStore.aws.namePrefix>cp/*` plus the bare key
`<secretStore.aws.namePrefix>cp`; with the default prefix `warden/` that is
`warden/cp/*` and `warden/cp-??????` (Secrets Manager appends a six-character
suffix to a secret ARN). Add an explicit deny to every worker role, using your
own prefix if you changed it, so it holds even if a later `warden/*` grant is
widened:

```json
{
  "Sid": "NeverTheReservedCpNamespace",
  "Effect": "Deny",
  "Action": [
    "secretsmanager:GetSecretValue",
    "secretsmanager:PutSecretValue",
    "secretsmanager:CreateSecret",
    "secretsmanager:DeleteSecret",
    "secretsmanager:UpdateSecret"
  ],
  "Resource": [
    "arn:aws:secretsmanager:*:ACCOUNT_ID:secret:warden/cp/*",
    "arn:aws:secretsmanager:*:ACCOUNT_ID:secret:warden/cp-??????"
  ]
}
```

Upgrade note: rename any existing `cp` or `cp/...` placeholder, `auth[]`
credential value or stored secret before upgrading. The control plane and the
workers refuse to load a config that names the reserved namespace.

### CP-only user credential store (`consent.store`)

Every per-user credential in P3 (IdP refresh tokens, provider grants, parked
revokes and OAuth client secrets) lives in one CP-only store, `consent.store`,
never in the distributed `secretStore`. The control plane hands workers its
`secretStore` selector (and, when configured, its explicit credential) over the
settings wire, so anything written there is readable by every worker; nothing
hands a worker a credential for `consent.store`. The block is part of the
CP-local `consent:` block: read from `--config` only, never on `/policy` or the
settings wire, and never mounted on `/central/secrets` or the dashboard secret
store tab.

```yaml
consent:
  enabled: true
  # oidc, session, idpLink ... as above
  store:
    backend: aws                 # aws | vault | echo (--dev only)
    namePrefix: warden-cp/       # default; must end with /
    aws:
      region: us-east-1          # required for aws
    # vault:                     # with backend: vault (KV version 2 only)
    #   addr: https://vault.example.com:8200   # https unless the host is loopback
    #   mount: secret            # a KV v2 mount; not sys, auth, identity or cubbyhole
    #   namespace: team          # optional (Vault Enterprise / HCP)
    #   tokenEnv: VAULT_TOKEN    # env var NAME (default VAULT_TOKEN), never the token
```

Logical keys (built only by the `secrets.UserKey` helpers; `<userKey>` is a
fixed 32-hex pseudonym of the user's issuer and subject):

| Key | Holds |
|-----|-------|
| `idp/<userKey>` | the user's IdP refresh token |
| `users/<userKey>/<provider>` | the user's grant for a provider |
| `revoking/<userKey>/<provider>` | a grant parked until its provider revoke succeeds |
| `oauth-clients/<provider>` | a provider's OAuth client secret |

With the default prefix the backend name of `idp/<userKey>` is
`warden-cp/idp/<userKey>`.

- **Credentials.** The AWS client takes credentials from the control plane's
  environment or instance role only (env, then IMDS); the Vault token is read
  from the CP environment variable named by `tokenEnv`. The block has no key or
  token field, and the strict parser rejects one.
- **Persistence.** With `consent.idpLink.enabled` (the default) the control
  plane refuses to start unless `consent.store` is configured with a backend
  that keeps values (aws or vault); no store and `echo` are refused, naming
  `consent.idpLink.enabled` and `consent.store.backend`. Set
  `idpLink.enabled: false` to run consent sign-in without a store.
- **Startup refusals.** The control plane refuses to start, naming both keys,
  when `consent.store.namePrefix` equals, starts with, or is a prefix of
  `secretStore.aws.namePrefix` on the same backend (compared after trimming,
  case-insensitively, and with the default prefix filled in). For AWS the region and
  account are not taken into account: a worker grant on a prefix usually spans
  regions, and the account behind a credential is not known before calling AWS.
  It also refuses a `consent.store` that nests with `keys.store.aws.namePrefix`
  and `backend: echo` without `--dev` (echo keeps no value). A settings write, rollback, applied draft or `warden policy
  import` that would move `secretStore` onto the `consent.store` namespace is
  refused with 400 `{"error":"user_store_overlap","detail":...}`.
- **Reserved namespaces.** `idp/`, `users/`, `revoking/` and `oauth-clients/`
  are reserved everywhere else, exactly like `cp/` above: config validation
  rejects a `secrets[]` placeholder under one with `invalid_secret_key: reserved
  namespace "<ns>/"`, a worker refuses one before any backend call, and
  `/central/secrets` and `/dashboard/api/secretstore` leave them out of `GET`
  and answer `POST` and `DELETE` with 403 `reserved_key`. No policy or console
  edit can make a worker swap in, read or overwrite a per-user credential.

Give only the control plane's role access to `warden-cp/*`. Worker roles, and
any credential you put in `secretStore.aws`, must never cover it. Example IAM
statements for the control plane role (use your own prefix if you changed it;
keep `warden-cp/*` with the slash, so it does not also match
`warden-cp-keys/`). `secretsmanager:ListSecrets` has no resource-level
permissions, so it needs its own statement on `"*"`; listing returns names and
metadata only, never values, and the names under `warden-cp/` carry only the
pseudonymous `<userKey>` and provider ids, never a subject or email:

```json
[
  {
    "Sid": "WardenCpUserCredentialStore",
    "Effect": "Allow",
    "Action": [
      "secretsmanager:GetSecretValue",
      "secretsmanager:PutSecretValue",
      "secretsmanager:CreateSecret",
      "secretsmanager:DeleteSecret"
    ],
    "Resource": "arn:aws:secretsmanager:*:ACCOUNT_ID:secret:warden-cp/*"
  },
  {
    "Sid": "WardenCpListSecrets",
    "Effect": "Allow",
    "Action": "secretsmanager:ListSecrets",
    "Resource": "*"
  }
]
```

And an explicit deny on every worker role, so it holds even if a later grant
is widened:

```json
{
  "Sid": "NeverTheUserCredentialStore",
  "Effect": "Deny",
  "Action": "secretsmanager:*",
  "Resource": "arn:aws:secretsmanager:*:ACCOUNT_ID:secret:warden-cp/*"
}
```

#### Vault KV v2 backend (`backend: vault`)

The Vault store speaks the KV version 2 HTTP API. The token is read once at
startup from the control plane's environment variable named by `tokenEnv`
(default `VAULT_TOKEN`); no YAML key, settings field or bundle carries it, and
no log line or error holds it. Before it serves anything the control plane
probes the mount (`GET /v1/sys/internal/ui/mounts/<mount>`, the preflight the
`vault kv` CLI runs) with that token and namespace, and refuses to start when:

- the variable is empty (the error names it);
- the mount is not a KV version 2 engine rooted at exactly `mount`
  (`secrets.ErrNotKV2`; a KV v1 mount would silently ignore compare-and-swap
  and turn `metadata/` into an ordinary secret);
- the mount or the namespace does not exist (404). A 404 at startup is never
  read as an empty store;
- the token has no capability on the mount (403), or Vault is unreachable.

`addr` must be https unless the host is loopback (the token travels on every
request), redirects are never followed, and `mount` may not be a Vault system
path (`sys`, `auth`, `identity`, `cubbyhole`). Every new key is written with
`max_versions=1`, so an overwritten refresh token is not recoverable from
Vault's version history.

A policy attached only to the control plane's token, and no worker policy that
names the path (use your mount and prefix if you changed them):

```hcl
# warden-cp: the control plane token only
path "secret/data/warden-cp/*"     { capabilities = ["create", "read", "update", "delete"] }
# Every write first sets max_versions=1 on the key's metadata, so writes need
# create and update on metadata/ too; Delete removes every version there.
path "secret/metadata/warden-cp/*" { capabilities = ["create", "read", "update", "list", "delete"] }
```

The startup probe needs no rule of its own: Vault answers
`sys/internal/ui/mounts/<mount>` for a token that holds any capability on a
path inside the mount, and the two rules above are inside it. Do not grant a
broader path such as `secret/*` to make the probe pass; a 403 from the probe
means the token or the namespace is wrong.

Two mount-level settings are recommended as a backstop:

- `vault write secret/config max_versions=1`: even a key written outside
  Warden keeps one version.
- `cas_required`: the store writes with `options.cas` (compare-and-swap) where
  it reads a version first, and a plain `Put` fails on a `cas_required=true`
  mount. Leave `cas_required` off on the consent.store mount (or the key
  metadata) until every writer of it uses compare-and-swap.

`List` walks `metadata/` and can return a key whose `Get` is not found (its
data was soft-deleted); callers treat that as absent.

Upgrade note: an existing `secrets[]` placeholder or `auth[]` credential value
under `idp/`, `users/`, `revoking/` or `oauth-clients/` now fails validation with
the message above; rename it before upgrading. Other placeholders are
unaffected.

## Per-user secrets config (`perUserSecrets:`)

`perUserSecrets` turns on per-user credentials (P3 "Act as the user"): a
per-user placeholder is swapped for the calling user's own access token,
minted by the control plane from the grant that user connected in the consent
portal. It is a CP-local top-level block, a sibling of `secretStore`. It is
off by default; with the block absent or `enabled: false`, `GET /policy`, its
ETag, the signed bundle and worker behaviour are unchanged. The block is never
on `GET /policy` or the settings wire; workers receive the value-free mappings
only as a signed-bundle section. It holds no secret: grants live only in
`consent.store`.

```yaml
perUserSecrets:
  enabled: true
  workerCacheTTL: 5m              # default 5m; allowed 30s to 15m
  mappings:
    - placeholder: GOOGLE_USER    # 8-128 characters of [A-Za-z0-9_{}-]
      provider: google            # a consent.providers id
      scopes: [https://www.googleapis.com/auth/gmail.readonly]
      domains: [gmail.googleapis.com]   # required; allowlist domain grammar
      in: [header]                # header and/or query; default [header]
      agents: [support-bot]       # required; the bound agent ids allowed
```

Validation (only while `enabled` is true, so a half-written disabled block in
the served copy never blocks a start): `domains` is required and uses the
allowlist grammar (exact, `*.suffix`, `~regex`); `in` is `header` and/or
`query` (the body is not supported, so a mapping never buffers a body);
`provider` is a provider id (`^[a-z][a-z0-9-]{0,31}$`); every agent is a valid
agent id; scopes are non-empty, without whitespace and without duplicates.
A per-user placeholder must not equal, contain or be contained in a static
`secrets[]` placeholder or another mapping's placeholder, because the static
swap replaces substrings (`GOOGLE` and `GOOGLE_USER` are refused together).
The strict parser rejects any other key, so no value or token field exists.

With `enabled: true` the control plane refuses to start, naming the missing
key, unless:

- `consent.store` is configured (with `consent.enabled`) on a backend that
  keeps values (aws or vault);
- `tokenService.enabled` is true (only a bound Warden token can release a
  user's credential);
- `--bundles` is `offer` or `require` (the mappings and revocations reach
  workers only in the signed bundle);
- every mapping's `provider` is listed in `consent.providers`.

## Worker CA (`workerCA:`)

The worker CA is a CP-held intermediate that issues short-lived worker client
certificates (W-P2-WCA-01; enrollment and renewal arrive in the follow-up
tickets). It is a separate trust root from the proxy MITM CA: compose workers
hold `proxy-ca.key`, so an intermediate under it would let any worker mint
certificates for any other. The block is CP-local like `keys:` (read from
`--config` only, never served to workers) and off by default; without it
nothing is loaded. See `configs/config.example.yaml` for every key.

Create the CA once:

```sh
warden control-plane ca init --out-dir ./worker-ca --trust-domain warden.local \
  --state-dir /var/lib/warden-cp [--config F] [--key-source keys|file] [--force]
warden control-plane ca csr --state-dir /var/lib/warden-cp   # intermediate key + CSR for an offline root
```

`ca init` writes a P-256 root (10 years) and an intermediate (1 year, path
length 0, restricted to URI names in the trust domain) to `--out-dir`:
`root.key` (0600, **move it offline and delete it from this host**),
`root.crt` and `intermediate-chain.pem` (what `workerCA.certFile` points at).
The intermediate key goes to the key manager (`--key-source keys`, purpose
`ca`; needs the state dir to have run once with `keys.enabled`) or, for
development, to `intermediate.key` in `--out-dir` (`--key-source file`, mode
0600, point `workerCA.keyFile` at it from outside `--state-dir`). It never reads
the proxy CA, and refuses to overwrite files or an existing `ca` key without
`--force` (which needs the control plane stopped when it replaces a key, and
checks that before it writes any file; files are staged and renamed into place
only after the key is stored, the chain file last; leftover `.ca-*.tmp` files of an interrupted run are removed at the next start).

For an offline root: stop the control plane, run `ca csr` (the key goes to the
key source, the CSR to stdout), have the root sign it, install the chain at
`workerCA.certFile`, start the control plane. Until then it runs degraded. An
expired `workerCA.previousCertFile` is ignored with a WARN. The pinned
intermediates are verified from startup, even while the key backend is down;
only issuing waits for the key.

At startup the control plane checks the intermediate (CA, path length 0,
certSign, not expired, key matches) and that it neither equals nor chains to
`--ca-cert`, and exits before listening otherwise. An intermediate under 30 days
from expiry logs a WARN with `not_after`. If the key backend is unreachable the
control plane starts degraded: `/healthz` reports `degraded: worker_ca key
unavailable` (still 200), enrollment and renewal answer 503, and the load is
retried every 30 seconds. One startup line carries `worker_ca=enabled`,
`trust_domain`, `intermediate_subject`, `not_after` and `key_source`; keys, PEM
blocks and CSRs never appear in logs.

### Worker enrollment (`enroll-token`, `POST /control/enroll`)

With `workerCA.enabled` and `--state-dir`, a worker trades a one-time `wet_`
enrollment token and a CSR for a worker certificate at `POST /control/enroll`.
The route needs no session or client certificate (the token is the credential)
and does not exist (404) otherwise. Mint tokens offline, with the control plane
running or stopped (a running one sees them within about 2 seconds):

```sh
warden control-plane enroll-token create --worker-id worker-1 --state-dir D          # printed once
warden control-plane enroll-token create --worker-id-prefix pool-a- --max-uses 3 --out tok --state-dir D
warden control-plane enroll-token create --worker-id worker-2 --from-env WARDEN_WORKER_2_ENROLL --state-dir D
warden control-plane enroll-token list [--json] --state-dir D
warden control-plane enroll-token revoke --id et_... --state-dir D
```

A token is bound to one worker id (single use) or to an id prefix (up to 100
uses, for replica pools): the worker sends `workerIdSuffix` and its id is
prefix+suffix, which must match `^[A-Za-z0-9._-]{1,128}$`. The lifetime defaults
to `workerCA.enrollTokenTTL` and is capped by `enrollTokenMaxTTL` (pass
`--config` so the CLI reads them). Only the sha256 of a token is stored. Create
and revoke are admin-audited as `cli`; each enrollment appends a
`worker.enrolled` row (actor `enroll:<token id>`). An unknown, used-up, expired
or revoked token is the same `401 unauthorized`; a bad CSR or suffix is a 400
that leaves the token unused; more than 10 requests a minute per address or per
token is a 429; a degraded CA is a 503 before the token is touched.

The per-address limit keys on the TCP peer address and never trusts
`X-Forwarded-For`, so behind a load balancer or ingress the whole fleet shares
one 10 per minute budget per address. TODO: key it on the client IP resolved
through `console.trustedProxies` (the resolver in `adminaudit_mw.go`).
Re-running `create` with the same name, value and binding is always a no-op,
even after the token was used up, expired or revoked: it is never revived or
extended, and the command prints its state.

#### Enrollment tokens API and console panel

Admins can do the same without shell access to the state dir, under
`/dashboard/api/worker-enrollments` (404 unless `workerCA.enabled` with a state
dir; the console's Fleet page shows a "Worker enrollment tokens" panel for admins):

| Request | Role, API key scope | Result |
|---|---|---|
| `GET /dashboard/api/worker-enrollments` | admin, `workers:admin` | 200, every token (revoked included): `id`, `name`, `workerId` or `workerIdPrefix`, `maxUses`, `uses`, `createdBy`, `createdAt`, `expiresAt`, `revokedAt`. Never the token or its hash. |
| `POST /dashboard/api/worker-enrollments` `{name, workerId or workerIdPrefix, maxUses?, expiresIn?}` | admin, session only (`none`) | 201 with the metadata and `token`, the only time the plaintext is shown (`Cache-Control: no-store`). 400 for invalid input, an unknown field or an `expiresIn` above `workerCA.enrollTokenMaxTTL`, 409 for a taken name, 413 over 8 KiB. |
| `DELETE /dashboard/api/worker-enrollments/{id}` | admin, `workers:admin` | 204, idempotent: the token's next `POST /control/enroll` is a 401. 404 for an unknown id. |

Minting a credential is never available to an API key. With `console.auth: none`
a POST or DELETE answers 403 `{"error":"use_cli"}` and GET still lists. Create
and revoke are admin-audited as `worker_enroll_token.create` and
`worker_enroll_token.revoke` (target `worker_enrollments`, target_ref
`enroll_token:<id>`); the audit state hash covers token metadata only, so no row
holds the token or its hash.

### Worker certificate authentication and `POST /control/renew`

With `workerCA.enabled` and TLS (`--ca-cert`/`--ca-key`), the listener asks every
client for a certificate but verifies nothing in the handshake. The worker
authenticator judges a presented certificate on each request to `/policy`,
`/control/heartbeat` and `/central/ingest`: it must chain to a pinned worker
intermediate, carry clientAuth, have exactly one `spiffe://<trust domain>/warden/worker/<id>`
URI SAN, be inside its validity window by the control plane clock and not be
revoked. Anything else is a uniform `401 unauthorized` (never a handshake error),
the request is **not** retried against a bearer in the same request, and the
reason (`bad_chain`, `bad_eku`, `bad_san`, `expired`, `revoked`) goes only to the
rate-limited `worker auth rejected` log line with the serial. The worker id is the
SAN's: a missing `X-Warden-Proxy-ID` header resolves to it and a different one is
a `403 proxy id mismatch`. The fleet view shows `authKind=cert`, `certSerial` and
`certNotAfter`; `warden_cp_worker_auth_total{kind=cert,outcome}` counts the results.

Verification uses the intermediates pinned at startup, so it keeps working while
the CA key is degraded (only enrollment and renewal answer 503). The revoked-serial
index is in memory (no database access per request), is reloaded on the 2 s
`PRAGMA data_version` poll and keeps the last good set when a reload fails. Until
the first load succeeds, and when there is no `--state-dir`, certificates are
refused. `/central/secrets` and `/dashboard/*` never accept a worker certificate:
a request that presents one and no bearer of its own gets 401 on `/central/secrets`
in every method.

Modes: with workerCA enabled, the open, mixed and `--require-worker-tokens` modes
accept a certificate next to their tokens. `--require-worker-certs` (default off)
accepts certificates only, logs `auth_mode=strict-certs`, and refuses to start
without workerCA, `--state-dir` and TLS, or together with `--require-worker-tokens`
or `--legacy-token-env`.

`POST /control/renew {"csr": "<PEM>"}` is authenticated by the certificate alone (a
bearer is a 401). It needs a P-256 or Ed25519 CSR for a new public key (400
`same_key` otherwise) and a lineage head: the worker's latest certificate (rows
revoked as `enroll_failed` or `renew_failed` do not count), or its predecessor
within 10 minutes when this control plane has not seen the successor used (a lost
response; up to 3 retries). A grace renewal revokes that unused successor
(`revoke_reason=superseded`), so only one descendant of the predecessor stays valid;
presenting a superseded serial later, or a renewal from any other serial, revokes the
worker (all its certificates and its unused id-bound enrollment tokens), cuts off its
held long-polls and appends `worker.cert_lineage_conflict`; the worker must re-enroll
with a new token. "Seen" is kept in memory: a control plane restart clears it, which
widens the grace (a successor that was in use looks unseen for the first 10 minutes).
The new key must differ from the presented certificate's and the three before it.
A successful renewal inserts `worker_certs` with `issued_via=renew` and `prev_serial`
and returns 201 with the enrollment response shape plus `prevSerial`; it is logged
and counted (`warden_cp_worker_renew_total{outcome}`), not admin-audited. At most
one renewal per worker per 10 minutes (429 with `Retry-After`; only a committed
renewal spends it), 30 requests a minute per remote address, 503 `ca_unavailable`
while the CA is degraded.

#### Revoking a worker

An admin revokes a worker's certificates from the fleet view (Revoke button, with
`console.auth: oidc`), by `POST /dashboard/api/workers/{id}/revoke` (optional body
`{"serial": "<hex>"}` to revoke one certificate; 200 `{"revoked": n, "enrollTokensRevoked": m}`, 404 for an unknown
worker or a serial that is not its own, 403 for a viewer), or offline:

```sh
warden control-plane worker revoke --id worker-1 [--serial S] --state-dir D
```

It sets `revoked_at`, `revoked_by` and `revoke_reason=admin_revoked` on every unexpired
certificate of the worker and revokes its unused id-bound enrollment tokens, so a later
renewal is refused and the worker must re-enroll with a new token. It is idempotent
(`revoked: 0` the second time; `enrollTokensRevoked` counts the unused id-bound tokens it revoked, and the audit row records `enroll_tokens_revoked`). Revocation is enforced on the control plane only, through
the in-memory index: the worker's next `/policy`, `/control/heartbeat`, `/central/ingest`
or `/control/renew` is a 401 and its held `/policy` long-poll ends at once; it keeps its
last-known-good policy. The console route refreshes the index synchronously; the CLI is
picked up by a running control plane within its 2 s `data_version` poll. Each revoke writes
one admin audit row (`worker.revoked`, target `worker_certs`, target_ref `worker:<id>`,
details `worker_id` and `count`; auth_method `cli` for the CLI) and logs `worker certs
revoked`. `warden_cp_worker_cert_revoked_total` counts certificates revoked by this process.

Rows are pruned by the control plane: a revoked certificate stays in the index until its
`not_after`, and its `worker_certs` row is deleted 30 days after `not_after` (a row that a
surviving certificate names as `prev_serial` stays with it).

`workerCA.enabled` requires `--ca-cert` and `--ca-key`: enrollment tokens and
certificates never travel over plain HTTP, and the control plane exits before
listening otherwise.

## Migrating from per-worker tokens

Per-worker `wwt_` tokens are long-lived bearers. [Worker certificates](#worker-ca-workerca) replace
them with an mTLS client certificate that lives 24 hours, is renewed by the worker itself and can be
revoked at once. Nothing changes by default: `workerCA.enabled` and `--require-worker-certs` stay off
until you opt in, and a control plane with the worker CA enabled accepts a certificate next to the
tokens it already holds, so workers can move one at a time. The operations runbook is
[docs/runbooks/worker-certs.md](runbooks/worker-certs.md).

The compose recipe `deploy/compose/docker-compose.control-plane.yml` (and its signed-bundles overlay) is
already on certificates; the e2e stack, `docker-compose.yml`, the Claude Code and Codex recipes and the
other `configs/config*-worker.yaml` files keep per-worker tokens and follow the steps below when you
want them to move.

### Certificate lifecycle

- A certificate lives `workerCA.certTTL` (default 24h, 1h to 7d) and carries one SAN,
  `spiffe://<trustDomain>/warden/worker/<id>`; the id is the worker's identity everywhere (a
  different `X-Warden-Proxy-ID` is a `403`).
- The worker renews at about 50% of the lifetime (plus or minus 10%, measured on its own monotonic
  clock, so clock skew does not move it) with a fresh key, swaps the certificate in, rotates its
  connections to the control plane (a held long-poll presents the new certificate too) and persists it under `controlPlane.stateDir`. A failed renewal retries from 5 seconds up
  to 5 minutes. With the 24h default the worker tolerates a control plane outage of about 12 hours.
- An expired certificate gets no grace: the worker keeps its last-known-good (default-deny) policy,
  logs `worker cert expired` and must re-enroll. Watch `warden_worker_cert_expiry_seconds` and
  `warden_worker_cert_renewals_total{outcome}` (see the runbook).
- A restart reuses the persisted certificate: no new `worker.enrolled` audit row, no token read.

### Replica pools (prefix tokens)

A pool whose replicas cannot carry a stable id enrolls with one token bound to an id prefix:

```sh
warden control-plane enroll-token create --name pool-a --worker-id-prefix pool-a- --max-uses 20 \
  --config F --state-dir D --out ./pool-a.enroll
```

Every replica gets the same token value and a persistent `controlPlane.stateDir` of its own. It sends
a suffix (the host name, or the variable named by `controlPlane.enrollment.workerIdSuffixEnv`) and
becomes `pool-a-<suffix>`, which must match `^[A-Za-z0-9._-]{1,128}$`. The token is single-use per
replica up to `--max-uses` (at most 100) and expires after `workerCA.enrollTokenTTL`, so create it
when the pool scales up. Leave `central.proxyID` unset (or equal to the final id). A replica without a
persistent state directory enrolls again at every start and uses up a slot each time.

### TLS passthrough

The control plane reads the worker's certificate from the TLS handshake. A load balancer or ingress
that terminates TLS in front of it breaks worker mTLS: it must pass TLS through (layer 4, with
`--ca-cert` and `--ca-key` on the control plane itself). Forwarded client-certificate headers
(`X-Forwarded-Client-Cert`, `X-SSL-Client-Cert` and the like) are never trusted. Only the worker routes need
passthrough: give workers their own passed-through address if a terminating proxy fronts the console.

### Migration steps (no downtime)

Run them in order. Each step leaves every worker working, and a control plane restart is not an
egress outage: workers keep enforcing the last policy they pulled and reconnect when it is back.
`D` is the control plane's `--state-dir` and `F` its `--config` file.

1. **Create the worker CA** (production: `--key-source keys`, which needs `keys.enabled: true` and a
   state dir that has run once; development: `--key-source file`):

   ```sh
   warden control-plane ca init --out-dir ./worker-ca --trust-domain warden.example \
     --key-source keys --config F --state-dir D
   ```

   Move `./worker-ca/root.key` to offline storage and delete it from this host. The control plane
   only needs `intermediate-chain.pem`.
2. **Enable `workerCA` and restart the control plane with the token mode it already has.** Add to
   `F`:

   ```yaml
   workerCA:
     enabled: true
     trustDomain: warden.example
     certFile: /etc/warden/worker-ca/intermediate-chain.pem
     keySource: keys
   ```

   Copy `intermediate-chain.pem` from step 1's `--out-dir` (`./worker-ca`) to that `certFile` path
   on the control plane host.

   Keep `--require-worker-tokens` (or `--legacy-token-env`) as it is, and keep `--ca-cert` and
   `--ca-key` (the worker CA needs TLS). The startup line now also shows `worker_ca=enabled` and
   the tokens still work. Enrollment answers `503` until the key loads.
3. **Mint one enrollment token per worker** (the id is the worker's proxy id; a pool uses a prefix
   token, above):

   ```sh
   warden control-plane enroll-token create --name worker-1 --worker-id worker-1 \
     --config F --state-dir D --out ./worker-1.enroll
   ```

   Hand each worker its token through your secret mechanism (an environment variable), never in
   the config file. A token expires after `workerCA.enrollTokenTTL` (1h by default; the longest an
   operator may ask for is `enrollTokenMaxTTL`), so mint them just before the rollout, or pass
   `--expires-in`.
4. **Enroll the workers one at a time, while their tokens still work.** In the worker's config
   replace `controlPlane.tokenEnv` and `central.tokenEnv` with a persistent state directory and the
   enrollment variable, then restart that worker:

   ```yaml
   controlPlane:
     stateDir: /var/lib/warden-worker      # absolute path on a persistent volume
     enrollment:
       tokenEnv: WARDEN_WORKER_ENROLL_TOKEN
   ```

   Leave `central.proxyID` as it is (it must equal the worker id) and the endpoints unchanged. The
   worker enrolls on start, then pulls policy and ingests with its certificate.
5. **Confirm every worker is on a certificate.** `GET /dashboard/api/workers` (or the console's Fleet
   page) must show `authKind: cert` for every worker, with a `certSerial` and a `certNotAfter`
   about a day out. Wait for one renewal on one worker (`certSerial` changes after about 12
   hours, or watch `warden_worker_cert_renewals_total{outcome="ok"}`). A worker still showing `token`
   or `legacy` is not migrated yet: do not continue.
6. **Restart the control plane with `--require-worker-certs`**, replacing `--require-worker-tokens`
   (and without `--legacy-token-env`). The startup line says `auth_mode=strict-certs`. From now on
   a `wwt_` bearer, the shared token or an anonymous caller gets `401` on `/policy`,
   `/control/heartbeat` and `/central/ingest`. Only do this once step 5 is true for every worker,
   including workers that are rarely restarted: a worker you missed loses its policy updates and
   ingest and keeps only its last-known-good policy.
7. **Revoke the `wwt_` tokens**, after a soak period (see Rollback) in which nothing needed them:

   ```sh
   warden control-plane token list --state-dir D
   warden control-plane token revoke --id wt_... --state-dir D
   ```

   Then unset the old token variables everywhere they were distributed.

### Rollback

- **Before step 6** (tokens are still accepted): put `tokenEnv` back in the worker config, remove
  `enrollment`, restart the worker. Nothing else changes; its certificate is simply not used.
- **After step 6 but before step 7**: restart the control plane with `--require-worker-tokens`
  instead of `--require-worker-certs`. Workers on certificates keep working (a certificate is
  accepted next to the tokens) and workers can be switched back one at a time as above. This is why
  step 7 comes after a soak: revoked tokens cannot be un-revoked, and a replacement needs `warden
  control-plane token create`.
- **After step 7**: mint new tokens with `warden control-plane token create`, switch the workers
  back, and restart the control plane with `--require-worker-tokens`.
- A worker whose certificate was revoked or expired re-enrolls with a new token
  ([runbook](runbooks/worker-certs.md#re-enroll-a-worker)).

## Signed bundles (`--bundles`)

`warden control-plane --bundles=off|offer|require` lets the control plane sign
what it serves on `GET /policy` with its `purpose=bundle` signing key (see
Signing keys above). Unset it is `require` when `--state-dir`,
`--policy-store=versioned` and `keys.enabled: true` are present, and the legacy
unsigned policy with one startup WARN naming the missing piece when not (it never
stops a control plane that could not sign anyway); an explicit `offer` or
`require` without them refuses to start. `--bundles=off` is the explicit,
temporary opt-out and logs a WARN: `/policy` is byte-identical to before (same
body, same ETag, no signing, no extra work). Upgrade steps, mixed fleets and
rollback are in [Upgrading to required signed bundles](#upgrading-to-required-signed-bundles).
A worker that pins the key and verifies the envelope is described in
[Pinning bundle keys](#pinning-bundle-keys-worker-config).

- **Prerequisites.** `offer` and `require` need `--state-dir`,
  `--policy-store=versioned` and `keys.enabled: true`; startup fails with an
  error naming each missing piece, and also when no bundle key can be loaded. An
  unset `--bundles` is not an error: it is the legacy wire plus a WARN.
- **Negotiation.** A request with `Accept: application/vnd.warden.bundle.v1+json`
  gets the envelope with that `Content-Type`. Other requests get the legacy
  policy in `offer` and `406 {"error":"signed_bundle_required"}` in `require`.
  Each format answers `If-None-Match` and the `?wait=` long poll against its own
  ETag. The legacy ETag is unchanged; the envelope ETag is a 16-hex hash of the
  envelope bytes, so a re-sign changes it.
- **Sequence number.** `seq` is the newest `policy_publish_log` row, so a policy
  save, a rollback, a block-list change and a credential change each move it
  forward. A change to the token JWKS (a rotation or an emergency revocation)
  appends a row with reason `token_jwks` first, then signs. A bundle key change
  appends nothing: the same content is re-signed under the same seq, which a
  verifier treats as a refresh. The signed content for a seq never changes.
- **Token issuer.** With `tokenService.enabled`, the payload carries a top-level
  `tokenIssuer` (the value of `tokenService.issuer`) and `contentSha256` covers
  it, so a worker verifies Warden tokens against an issuer the signer vouched
  for and never against `cpID`. The member is omitted when the control plane
  mints no tokens. A change of it (an edited issuer, the token service switched
  on or off, also while the control plane was down) appends a row with reason
  `token_issuer` first, like a JWKS change, so one seq never covers two issuers.
  The agent key thumbprints a worker compares with a token's `cnf.jkt` are the
  `registeredAgents[].jkt` already inside the signed policy; a registry change
  appends an `agent_registry` row and moves the seq. `tokenService.issuer` must
  differ from `identity.issuer` (startup fails naming both keys, and while the token
  service is on a settings write or policy publish that sets `identity.issuer` to the token
  issuer is refused the same way), because the
  two token kinds are told apart by their issuer. Nothing but the issuer URL and
  public thumbprints is added: no key material reaches the bundle, logs or audit.
- **Per-user sections.** With `perUserSecrets.enabled` the payload carries two
  more sections, both covered by the signature and both absent otherwise (with
  the block absent or disabled the payload bytes, the ETag and the publish log
  are unchanged; the legacy wire never carries them). `sections.perUserSecrets`
  is the value-free mapping list (`placeholder`, `provider`, `scopes`, `domains`,
  `in`, `agents`) plus `workerCacheTTLSeconds`. `sections.userGrantEpochs` is
  `{userKey: epoch}`, keyed by the hashed user key (never a `sub` or an email);
  an epoch is the publish-log seq of the revocation, so it only grows. A worker
  that does not know the sections ignores them. The control plane re-reads the
  block from the served config on every build and runs the startup checks
  (consent.store, token service, signed bundles, registered providers) again:
  an enabled block that fails them is not served, and the section last served
  stays. A change of the block appends a `per_user_secrets` row first, like a
  JWKS change. A revocation (`EpochStore.Bump`, called by the portal revoke and
  offboarding) appends a `user_grant` row, records the epoch and signs a bundle
  that wakes the long poll. Entries older than 2 x the longest allowed
  `workerCacheTTL` (30 minutes) are pruned by a one-minute ticker, which appends
  no row. The `userGrantEpochs` bytes signed for a seq are frozen (kept in
  `bundle_state`, so also across a restart): a worker hashes every section byte,
  so a re-sign of one seq never differs, and a pruned entry leaves the section
  only with the next seq. `PUT /dashboard/api/per-user-secrets` (admin only; no
  API key) saves the block. It is refused with `409 workers_lack_capability`
  while a connected worker bound to an agent the save newly serves lacks
  `usersecrets/v1`; an admin may pass `?force=true`, which the admin audit
  records with the worker ids, and an editor gets `403 role_required`. A mapping
  added by editing the served config instead logs one
  `per_user_secrets_workers_lack_capability` warning naming those workers. An
  enabled block that fails the startup checks or cannot be read is not served
  (the last section stays), `/healthz` answers `degraded: perUserSecrets stale`
  and one line is logged per transition. The epoch table comes from migration
  `bundles/0002`, which is not optional (the block can be enabled at runtime):
  `schema_version` grows by one on every control plane running this build,
  feature on or off, so a backup taken on it cannot be restored on the previous
  binary.
- **Credential.** `settings.secrets.accessKeyId` and `secretAccessKey` are not in
  the signed payload. They travel in the envelope's unsigned `credentials`
  sidecar and the payload carries their SHA-256. Nothing logs either.
- **Freshness.** `--bundle-max-age` (default 24h, minimum 1h) sets `expiresAt`;
  the control plane re-signs the current content every max-age/4 with the same
  seq. `--bundle-seq-floor N` appends one `restore` row at seq N at startup when
  the publish log is below it: set it above the highest seq any worker reports
  after restoring a backup, or pinned workers reject new bundles as rollbacks.
- **Key rotation.** Workers pin the bundle key, so it rotates only by command and
  in steps (`keys rotate --purpose bundle --stage`, then `--activate`; see Keys
  CLI). While a key is staged every envelope carries two signatures, one per key,
  and a worker that pins either key verifies it; the log line `bundle signed`
  lists both kids. A key change re-signs the same seq, so it is a refresh to a
  worker. The activation checks the workers' reported `pinnedKids` first. Rollout
  order (offer, pin every worker, require), emergency rotation and
  `--bundle-seq-floor` after a restore are in the
  [key rotation runbook](runbooks/key-rotation.md#6-staged-bundle-rotation); the
  compose recipe
  [`deploy/compose/docker-compose.bundles.yml`](../deploy/compose/docker-compose.bundles.yml)
  exports the public JWKS and pins every worker to it.
- **Failure.** If signing fails, the control plane keeps serving the last
  envelope until it expires, logs `bundle sign failed` with the seq and kid, and
  `/healthz` answers `200 degraded: bundle signing failed`. With no envelope,
  a request for one gets `503 {"error":"signed_bundle_unavailable"}`. An
  envelope over 4 MiB is not published and is logged at error. It never serves
  unsigned data to a request that asked for the envelope.

## Token endpoint (RFC 8693)

`tokenService.enabled: true` mounts `POST /oauth2/token` and
`GET /.well-known/oauth-authorization-server` (RFC 8414) on the control plane. With the block
absent or disabled both answer 404, no `tokensvc` table is created and `/policy` is
byte-identical; the block is the only switch (no flag) and never reaches a worker. See the
commented block in `configs/config.example.yaml` for every key and default.

The operator and harness-author guide (the flow, request and error examples, the reason enum, rate
limits, records and degraded modes) is [token-service.md](token-service.md); this section is the
route-level reference.

- **Startup checks.** Enabling needs `--state-dir`, a served `identity:` block with an issuer
  and audience (subject tokens are verified against the same IdP as workers, narrowed to
  `tokenService.allowedAZP`), `keys.enabled: true`, and `keys.token.overlap` of at least
  `ttl + 2m`. The issuer must be an absolute https URL without trailing slash, query or
  fragment (http only for a loopback host, logged as a warning). One INFO line reports
  enabled, issuer and ttl. A token key that has not loaded yet does not stop startup: the
  endpoint answers 503 `signer_unavailable` and `/readyz` reports it.
- **Request.** `application/x-www-form-urlencoded` only, body at most 32 KiB, no query string,
  no duplicate parameters, no `Authorization` header of any scheme (a session cookie, a `wwt_`
  worker token or a `wak_` API key is never client authentication), no `actor_token` or
  `resource`. `grant_type` must be `urn:ietf:params:oauth:grant-type:token-exchange` and the
  client authenticates with `client_assertion_type`
  `urn:ietf:params:oauth:client-assertion-type:jwt-bearer` plus `client_assertion`; an optional
  form `client_id` must equal the assertion's `iss`.
- **Response.** 200 `{access_token, issued_token_type, token_type: "Bearer", expires_in,
  scope?}` with `expires_in` equal to `exp - iat`. Errors are RFC 6749 section 5.2 JSON
  `{error, error_description}`: 400 for `invalid_request`, `invalid_grant`,
  `unauthorized_client`, `invalid_scope`, `invalid_target` and `unsupported_grant_type`, 401
  `invalid_client`, 503 `temporarily_unavailable` with `Retry-After`. With the IdP unreachable,
  a subject token under a cached kid still verifies, and a cold key cache or a kid missing from
  the cache gives 503 `idp_unavailable` (retry), never `invalid_grant`/`subject_invalid`, so an
  IdP outage during a key rotation does not force a new sign-in. `error_description` is a
  fixed word from a closed set and never echoes a token, assertion or claim; every
  `invalid_client` answers the same `client_authentication_failed`, so an unknown agent, an
  unknown key, a bad signature, a replay and a disabled agent cannot be told apart. Every reply
  carries `Cache-Control: no-store` and `Pragma: no-cache`.
- **Publish-window guard.** A token is minted only with a key that has been published for at
  least one policy long-poll wait plus worker skew (2 minutes), judged from the key's persisted
  `publish_at`, so a restart does not reset it. Normal rotations never wait (the prepublish
  window covers it); the first key after creation, and an emergency promotion of a barely
  published key, answer 503 `signer_unavailable` with `Retry-After` for about 2 minutes.
  Consumers of `/.well-known/jwks.json` must refetch on an unknown kid (rate-limited); Warden
  workers never use it (they take token keys from signed bundles). The key must also be in the
  JWKS the control plane serves. With signed bundles on (`--bundles=offer|require`, or unset with the prerequisites) it must also
  be in the token JWKS of the bundle served now (the last one signed, which stays served while
  the publisher is degraded), because a pinned worker holds token keys only from there; until
  that bundle is signed the service answers `signer_unavailable`. This covers the first key and
  an emergency rotation, and a degraded bundle publisher. With bundles off the check is skipped.
- **Agent registry cache.** The control plane has one registry store; it serves reads from a
  snapshot that its own writes invalidate at once and that a 2 s watch refreshes for other
  processes, so an agent disabled with the offline CLI stops authenticating within about 2 s.
- **Discovery and the issuer path.** The metadata is served at the bare
  `/.well-known/oauth-authorization-server` path only. RFC 8414 section 3 puts the path of an
  issuer that has one after that segment, which is not mounted, so use an issuer with no path
  component if clients rely on discovery (token exchange itself works with any path).
- **Revoking token sessions (admin).** A token session is one user at one IdP using one agent;
  its `wts_` sid is carried in every issued token and is an identifier, not a credential.
  `GET /dashboard/api/token-sessions?agent_id=&sub=&limit=&cursor=` lists sessions (sid,
  agent_id, idp_iss, sub, created_at, last_used_at, revoked_at; newest first, at most 200 per
  page, `next` is the cursor of the following page). `POST /dashboard/api/token-sessions/{sid}/revoke`
  answers 204 (also for a session that was already revoked) or 404 for an unknown sid, and
  `POST /dashboard/api/token-sessions/revoke` with `{sub?, idp_iss?, agent_id?}` (at least one
  field) answers `{"revoked": n}`, counting the live sessions it revoked. All three are
  admin-only, are 404 without `tokenService.enabled`, and in `console.auth none` need the admin
  bearer. The revokes are audited (`token_sessions.revoke` with target_ref `sid:<sid>`,
  `token_sessions.revoke_all` with target_ref `filter:agent=<id>` (or `filter` without an agent) and
  details `has_sub` and `has_iss`; like the block list, a subject or issuer is never recorded,
  not even hashed).
  A revoke sets `revoked_at` and keeps the row. The service reads the session table on every
  exchange, so the **next exchange takes effect at once**: one whose subject token was issued at
  or before `revoked_at` gets 400 `invalid_grant`/`session_revoked`, and the user must sign in
  again (a subject token issued after the revoke starts a new session). A revoked row is kept
  until the identity max token TTL plus clock skew has passed, so it is never pruned while a
  subject token issued before it could still verify. **A revoke does not recall tokens already
  minted**, and an exchange whose session check committed just before the revoke can still
  return its token after the revoke answers; it is the same as any already-minted token. Workers verify a Warden token offline against signed JWKS and have no revocation
  list, so a token issued before the revoke stays valid until its `exp` (at most
  `tokenService.ttl`, default 15m, and never past the user's own proof). To stop traffic sooner,
  also block the user (block list), disable the agent, or rotate the token key. A user-wide
  revoke only touches sessions that exist: a user with no live session (never exchanged, or idle
  past `session.idle`) has nothing to revoke, so block the user to also refuse a new one.

## Block list: offline CLI

The user block list lives in `<state-dir>/warden-cp.db`, outside policy
versions. When the console or the IdP is unavailable, or a script needs to
block someone without a browser session, use the command line. It works with
the control plane running or stopped.

```sh
warden control-plane block add --state-dir D [--sub S] [--email E] --reason R
warden control-plane block remove --state-dir D --id ID
warden control-plane block list --state-dir D [--json]
```

- `add` needs `--sub`, `--email` or both, and prints the new id. It uses the
  same store and validator as the admin API: the email is lowercased, a
  duplicate sub or email is refused, the reason is at most 512 bytes with no
  control characters, and the count and size limits apply. A validation error
  exits 1 with the API's message.
- `remove` exits 2 for an id that is not on the list. With approvals enabled on
  the state dir it exits 0, prints the id of a pending change draft and removes
  nothing; the row it appends is a `blocked_users.remove` row targeting
  `change_draft` (`draft:<id>@r1`, op `held`). `add` is always immediate.
- `list` opens the database read-only.
- `--admin-audit-key-file` (add and remove) defaults to `<state-dir>/cp-audit.key`.

**Audit.** With admin audit enabled in the state dir, each add and remove
appends one `blocked_users.add` or `blocked_users.remove` row (actor
`cli:<os user>`, auth_method `cli`, target `blocked_users`, target_ref
`block:<id>`). The reason text is not recorded in the row or logged. The
audit key is checked first: with audit rows present and the key missing or not
matching, the command exits non-zero and writes nothing. If the audit append
still fails, an add is rolled back and a remove deletes nothing. The block and
its audit row are two commits, not one transaction, so a crash between them
(or two concurrent removes of one id) can leave one without the other. A state dir where audit was never enabled
gets a one-line notice and no row.

**Pickup.** A running control plane polls `PRAGMA data_version` every 2 s and,
when another process wrote, refreshes the served policy and runs the block
store's change callbacks. A connected worker then receives the new list within
2 s plus one long-poll round trip.

The CLI has no console identity, so the self-unblock check of the admin API does
not apply. Write access to the state dir already allows policy changes, so
this adds no new authority.

## Worker admin token

The worker's admin listener (`:9090`, default `127.0.0.1:9090`) serves the same
dashboard as the control plane, with live writers for detection, integrations and the
managed secret store. Those writes use the same guard as above, with a **worker admin
token** that is separate from the control-plane token (`Authorization: Bearer <worker
admin token>`, constant-time compare).

- **Configure it.** Name the env var that holds the token with `--admin-token-env
  <ENV>` or `admin.tokenEnv: <ENV>` in the worker config (the flag wins). The token
  is read from the worker's own environment; the compose files use
  `WARDEN_ADMIN_TOKEN`, defaulting to the demo value `dev-admin-token`. Surrounding
  whitespace is trimmed.
- **What needs the token.** Every state-changing call on the admin listener — any
  method but `GET`/`HEAD`:
  - every `/dashboard/api/*` writer (`PUT /dashboard/api/policy`,
    `PUT /dashboard/api/detection`, …),
  - every `/admin/*` writer — today `POST /admin/refresh-secrets` (drop the secret
    cache and refetch). A writer added under `/admin/` later is guarded by default.
- **Reads stay open.** `GET`/`HEAD` need no token: `/healthz`, `/metrics`, the
  dashboard pages and every `/dashboard/api/*` and `/admin/*` read.
- **Fail closed.** With no token configured (flag and key unset, the variable unset or
  empty or whitespace-only) every write is refused with `403` and a message
  that names `--admin-token-env` and `admin.tokenEnv`. A missing or wrong token is
  `401`.
- **UI.** The dashboard prompts for the admin token after a `401`, exactly as above.
- **Audit.** A refused write logs `worker dashboard write refused` (WARN) with the
  method, path, remote address and reason, never the token.
- Keep the admin port on loopback (the default) or a private network regardless.

```sh
WARDEN_ADMIN_TOKEN=$(openssl rand -hex 32) \
  ./warden run --config configs/config.yaml --admin-token-env WARDEN_ADMIN_TOKEN
curl -X PUT http://127.0.0.1:9090/dashboard/api/detection \
  -H "Authorization: Bearer $WARDEN_ADMIN_TOKEN" -H 'Content-Type: application/json' -d '{"enabled":true}'
curl -X POST http://127.0.0.1:9090/admin/refresh-secrets \
  -H "Authorization: Bearer $WARDEN_ADMIN_TOKEN"
```

## Identity verification

A worker can attribute traffic to the person behind an agent by verifying a user
token from an OIDC issuer (for example the reference Dex, see
[identity-dex.md](identity-dex.md)). It is **off unless
configured** and, in `attribute` mode, only **attributes**: it records who made a
request and never blocks one. `challenge` mode additionally refuses a caller with
no valid identity and tells it where to sign in (see
[Challenge mode](#challenge-mode)).

### The `identity` block

The same block is served to managed workers (in the settings document) and read
from local YAML by standalone workers. It holds no secrets.

```yaml
identity:
  defaultMode: attribute        # off (default) | attribute | challenge
  issuer: https://dex.example.com/dex
  audience: warden
  allowedAZP: [agent-harness, warden-cli]
  # optional:
  # internalIssuerURL: http://dex:5556   # how containers reach the issuer
  # jwksURL: https://dex.example.com/dex/keys
  # groupsClaim: groups
  # clockSkewSeconds: 60                 # 0..300
  # maxTokenTTLSeconds: 3600
  # signIn:                              # challenge mode only, see below
  #   clientID: warden-cli
  #   maxPending: 32
  #   startsPerMinute: 30

agents:
  - id: research-bot
    identity: attribute          # per-agent override of defaultMode (admin-only field)
```

- A worker resolves its mode from the `agents` entry whose `id` matches the
  agent id the worker uses (the single configured agent's id, otherwise
  `agent:<port>`), then `identity.defaultMode`, then off. `require` is a Phase 2
  mode: config validation rejects it, and a worker that is served it (a newer
  control plane) keeps its previous identity config and logs one warning.
- `acceptDexTokens` (optional boolean) says whether the worker accepts a user token straight
  from the IdP next to the Warden tokens the control plane mints: unset is true when `issuer` is
  set and false otherwise; `false` refuses each IdP token as `unbound_token`, and then `attribute`
  needs no `issuer` or `audience` (challenge still does). `true` needs an `issuer`. See
  [identity-contract.md](identity-contract.md#warden-tokens-phase-2).
- `acceptDexTokens: false` with `challenge` mode is valid but logs a warning: the device
  sign-in hands out IdP tokens that the worker then refuses (`unbound_token`), so clients must
  exchange them for Warden tokens at the token endpoint.
- `issuer` and `audience` are required once any mode is `attribute` or `challenge`, unless
  `acceptDexTokens` is `false` in `attribute` mode. An `http`
  issuer is rejected unless `internalIssuerURL` is set; use `internalIssuerURL`
  when workers reach the issuer on a container network (`http://dex:5556`) while
  tokens carry the public issuer.
- `allowedAZP: [agent-harness, warden-cli]` is the recommended value for the
  reference Dex clients. There is no built-in default: empty means no `azp` check.
- The worker builds the verifier at startup **without contacting the issuer**; keys
  are fetched on the first token. A worker with the issuer down still starts and
  serves, and tokens it cannot verify are recorded as unverified and allowed.
- A settings change hot-reloads with no restart. The verifier is rebuilt only when
  `issuer`, `internalIssuerURL`, `audience`, `jwksURL`, `allowedAZP`, `groupsClaim`,
  `clockSkewSeconds`, `maxTokenTTLSeconds` or `acceptDexTokens` change; a mode-only change swaps the
  mode and keeps the verifier. A failed rebuild keeps the previous config and logs
  one warning (no token data).

### Challenge mode

`defaultMode: challenge` (or `agents[].identity: challenge`) makes the worker
refuse a CONNECT that has no `valid` identity with `407` and a sign-in URL: the
worker starts an RFC 8628 device authorization at the issuer and returns the
verification URL and user code; the **client** shows them, polls the issuer,
stores the token and retries (`warden identity exec --challenge` does this; the
wire contract is in [identity-contract.md](identity-contract.md#challenge-mode-407-with-a-sign-in-url)).
The worker stores no user token and no refresh token (ADR 0002). The `407` comes
before the block list, the policy check and any dial. `unverified` (the issuer's
keys could not be fetched in time) fails **closed** in this mode, unlike
`attribute`.

A client that sends `X-Warden-Challenge: in-tunnel` (`warden identity exec
--challenge-in-tunnel`) and a worker that terminates TLS (a CA is configured)
get the challenge **inside the tunnel** instead: the CONNECT is accepted, the offer
rides a response header the client strips, and the agent's first request gets a
`403` whose `error.message` holds the sign-in link, so an agent that never reads a
`407` body still shows it. No upstream is dialled and no policy runs. A worker
with no CA, an older worker, or a client that does not ask sends the `407`. See
[identity-contract.md](identity-contract.md#in-tunnel-challenge).

```yaml
identity:
  defaultMode: challenge
  issuer: http://localhost:5556/dex      # what tokens, the browser URL and the token endpoint use
  internalIssuerURL: http://dex:5556     # how the worker reaches the issuer
  audience: warden
  allowedAZP: [agent-harness, warden-cli]
  signIn:                                # optional, no secrets
    clientID: warden-cli                 # default warden-cli: a PUBLIC client; must be in allowedAZP when that is set
    scopes: [openid, email, profile, groups, offline_access, "audience:server:client_id:warden"]  # default shown
    maxPending: 32                       # open device authorizations per worker
    startsPerMinute: 30                  # device_authorization calls per worker
```

- With `allowedAZP` set, `signIn.clientID` must be in it, or every token from the
  flow would fail with `wrong_azp`; config validation rejects that. The block
  holds no secrets, and the client must be public (no secret on workers).
- The worker reaches the issuer through `internalIssuerURL` when set, and the
  `device_authorization_endpoint` and token endpoint it learns must be on the
  issuer's origin, as must the verification URLs it returns; anything else is
  dropped with `sign_in_error: issuer_unreachable`.
- A worker with no CONNECT listener (`proxy.mode: transparent`) cannot answer a
  `407`: it keeps its previous identity config and logs one warning. In `both`
  mode the transparent leg is not challenged.

**Rollout order (fail-open guard).** A worker that does not know `challenge`
rejects the settings and **keeps its previous config, so it keeps allowing**.
Upgrade the control plane first, then every worker, then set `challenge`. Workers
advertise the capability `identity/challenge-v1` on every heartbeat; while the
served settings turn challenge mode on, the fleet view marks each connected
worker without it with *identity: challenge not supported, still allowing*, and
the control plane logs `worker_lacks_identity_challenge` once per worker per
policy version. Do not rely on challenge mode until no worker carries that mark.

### Moving an agent from attribute to require

A worker that does not know `require` keeps its previous identity config, which is
attribute mode: it would let token-less traffic through for an agent you believe is
enforced. So the control plane guards the switch.

1. **Name every worker's agent.** Start each worker with `--agent-id` or set
   `central.agentID`. A worker that sends no agent id is shown as *agent unknown*
   and does **not** block a per-agent switch (the control plane cannot tell which
   agent it serves), but it does block `identity.defaultMode: require`.
2. **Upgrade the workers.** Workers on this build advertise `identity/require-v1` in
   every heartbeat. The Agents tab and the worker list show *N connected workers
   for this agent do not enforce require mode* (and *identity: require not
   supported, still allowing*) for any that do not.
3. **Save the mode.** `POST`/`PUT /dashboard/api/settings` (or applying a held
   change draft) that newly sets `agents[].identity` or `identity.defaultMode` to
   `require` is refused with `409 {"error":"workers_lack_capability","workers":[ids]}`
   while a connected worker serving that agent (any connected worker, for the
   default) lacks the capability. Nothing is written. "Connected" means a heartbeat
   or poll in the last 45 seconds; a worker that is offline is not listed, so a
   worker that reappears later without the capability is only flagged in the fleet
   view and logged once per policy version as `worker_lacks_identity_require`.
   Re-check the fleet view after every worker restart. An unrelated settings save
   while `require` is already in force is never refused for this reason.
4. **Force, if you must.** `?force=true` on the same request overrides the refusal.
   Only an admin may force; the admin audit row of the write records
   `force=true` and the refused worker ids (`workersLacking`, with the full
   `workersLackingCount`; the id list is cut at 100). The same parameter works on a
   policy rollback, on change draft submit and approve, and on a break-glass
   emergency apply, because each of them can newly set `require`. Applying a held
   draft re-runs the check, so force it on the approve (or emergency-apply) request.
5. **Roll back.** Set the agent's identity back to `attribute` (or `off`) in the same
   settings form; leaving require is never refused. If `identity.defaultMode` is
   `require`, clearing an agent's override does **not** leave require: the agent then
   inherits the default (and clearing it is guarded like any switch to require). Set
   the override to `attribute`, or change the default.

The guard decides per worker from the mode that worker would resolve (the agent's own
`identity`, else `identity.defaultMode`), so a new `require` default does not count a
worker whose agent keeps its own override, and clearing or removing an override under a
`require` default counts the workers of that agent.

**What the guard cannot see.** A worker's agent id and capabilities are what the worker
says in its heartbeat. With legacy shared-token or no worker authentication they are
unauthenticated claims, so the guard is advisory; it is binding only when workers
authenticate with worker tokens or mTLS certificates. The guard also lives only on the
control plane's write paths. Editing the served policy file directly and the offline
`warden policy import` bypass it; both are only caught afterwards, by the fleet view
flag and the `worker_lacks_identity_require` log line.

`agents[].identity` and `identity.defaultMode` are admin-only settings fields, so an
editor gets `403 role_required` for them, including through a policy rollback that
would change them.

### Where the token travels

- `Proxy-Authorization` on `CONNECT` works everywhere, with or without TLS
  termination: Basic with username `session` and the token as password, or
  `Bearer <token>`. It identifies the whole tunnel.
- `X-Warden-Identity: Bearer <token>` needs TLS termination (a CA configured), because
  Warden must read the request headers. On a tunnel it cannot
  decrypt it is never seen. Both headers are stripped before forwarding.
- In transparent mode there is no `CONNECT`, so only `X-Warden-Identity` on
  terminated traffic attributes. A worker in that mode logs a startup warning, as
  does attribute mode without a CA.
- Challenge mode on a raw tunnel (no CA) checks the token at `CONNECT` only; the
  tunnel is not cut when the token expires. With a CA, an expired token gets `403`
  `identity_expired` on the next request and the client is challenged again.

### Trust rules

- `sub` is authoritative. Email matching is only ever meaningful with a verified
  email (`email_verified: true`); an unverified email never identifies anyone.
- Only a token with status `valid` yields a policy subject, so group and user rules
  can never match an unverified caller.

### Limits and gaps

- A token is at most 16 KiB.
- The `CONNECT` request line is capped at 8 KiB and the header block at 64 KiB,
  with a 10 s deadline. Over a limit the worker answers 431 and records deny reason
  `malformed_connect` with detail `headers_too_large`.
- In transparent mode (no `CONNECT`) only `X-Warden-Identity` on terminated traffic
  attributes.
- A P1 identity is a **bearer assertion** signed by the IdP and **not yet bound to
  the agent**: whoever holds a valid token can present it. P2 adds binding and
  bundle-distributed JWKS.

### Identity metrics

Every identity check increments one counter,
`warden.identity.verify.total` (Prometheus `warden_identity_verify_total`), with
three bounded labels. There is no separate failure or success counter.

| Label | Values |
|---|---|
| `result` | `off`, `none`, `valid`, `invalid`, `expired`, `unverified`, `conflict` |
| `reason` | `none` (no reason), `bad_signature`, `wrong_iss`, `wrong_aud`, `wrong_azp`, `unknown_kid`, `alg_not_allowed`, `malformed`, `too_large`, `ttl_too_long`, `jwks_unavailable`, `wrong_nonce`, and the binding reasons `agent_mismatch`, `cnf_mismatch`, `agent_disabled`, `agent_unregistered`, `unbound_token`, `missing_claim` |
| `token_type` | `idp`, `warden`, `none` (no token, or one that never reached a verifier) |

A value outside these sets is recorded as `other`, so a bug or hostile input can
never create a new series. Labels never carry `sub`, email, `sid`, `jti`, `kid`,
an agent id or token material.

`warden.blocked.total{reason}` also takes `identity_required`, `identity_expired`
and `identity_conflict` (declared in `internal/denyreason`).

`warden.controlplane.clock_skew_seconds` (no labels) is the control plane's `Date`
header minus the worker's clock, set on every long-poll response; positive means
the control plane is ahead. The header has one-second resolution. Use it to
diagnose mass `expired` or not-yet-valid failures.

`GET /dashboard/api/analytics` gains an `identity` block built from stored events:
`byStatus` (counts by `identity_status`) and `topReasons` (the five most frequent
`identity_reason` values in the range). It is omitted when no event in the range
carries identity fields.

Agent binding (W-P2-WBND-02): a worker serves exactly one agent, and every
Warden token it verifies is checked on every request against the registered
agents of the bundle currently applied: the token's `act.sub` must be that agent,
the agent must be active, and `cnf.jkt` must be one of its registered key
thumbprints (`agent_unregistered`, `agent_disabled`, `agent_mismatch`,
`cnf_mismatch`, in that order). This is agent match plus key liveness within one
long-poll cycle, **not** proof of possession: a token is a bearer credential. A
derived worker id such as `agent:8080` matches a registry id only when identical, so bind
the worker with `--agent-id`. Events and decision lines of a valid Warden
identity carry the agent (`user_act` on events, `user.act` on the decision line)
and `identity_token_type`; no token or `cnf` value is ever logged.

Recommended alerts:

- The non-valid share per worker, for example
  `sum by (instance) (rate(warden_identity_verify_total{result!="valid"}[15m])) / sum by (instance) (rate(warden_identity_verify_total[15m])) > 0.2`.
- `warden_identity_verify_total{token_type="idp"}` for deprecation tracking: it
  should fall to zero once every harness uses Warden tokens.
- `warden_identity_verify_total{result="expired"}` rising during a control plane
  outage (tokens cannot be renewed); check `warden_controlplane_clock_skew_seconds`
  before blaming the outage.

### Require mode: session closing and degraded modes

In `require` mode (W-P2-WBND-09) the worker registers each session that holds a
verified Warden token in the block list's session registry and closes it at the
token's `exp` (raw tunnels and WebSockets at `exp` plus `identity.clockSkewSeconds`;
see [the identity contract](identity-contract.md#closing-sessions-at-token-expiry-w-p2-wbnd-09)).
It also re-checks them after each applied bundle, so a removed key, a disabled
agent or a rotated-out signing key ends open tunnels at the apply instead of at
token expiry. Each cut is one deny event (`identity_expired`, or `identity_required`
with the verifier reason in the decision log) and one `warden.blocked.total` count.

Degraded modes:

- **Control plane down:** a require-mode agent keeps working until its current
  token expires (at most 15 minutes, one token TTL), then its sessions are closed
  and new CONNECTs get the 407, so it fails closed one TTL later. Tokens cannot be
  renewed while the control plane (and its token service) is unreachable.
- **Dex down:** only new exchanges fail (`login_required` once the cached ID token
  ends). Existing Warden tokens and sessions are unaffected until their `exp`.
- **Restart with the control plane down:** the worker reloads its bundle only from
  the opt-in [last-known-good cache](#last-known-good-bundle-cache-opt-in) (`controlPlane.stateDir` with pinned keys); without it the
  worker has no token keys and stays fail-closed (`jwks_unavailable`).

Runbook: after a scheduled signing-key rotation the control plane refuses to mint
with a new key until the bundle that publishes it is signed. If the bundle
publisher is degraded at that moment (`/healthz` answers `200 degraded: bundle
signing failed`), minting stops (`503 signer_unavailable`) until the next
successful bundle sign, while tokens already minted keep working until `exp`.
Fix the publisher (signer key, bundle store) and the next sign lifts the guard; do
not disable bundles to get around it.

### Block list enforcement

A worker denies every request from a user on the block list (`policy.blockedUsers`,
by IdP `sub` and/or email). The list lives in the worker's policy evaluator and is
swapped with allow/deny, at boot, on every long-poll update and for standalone
YAML. It is checked at `CONNECT` (a `403` with `{"error":"user_blocked"}` before any
dial, TLS or raw tunnel) and again on every request (HTTP/1.1 keep-alive, h2, gRPC
streams and WebSocket upgrades, before any policy gate, judge or secret swap). Each
deny records reason `user_blocked` and ends the session. `sub` is an exact match;
email is matched case-insensitively.

Matching uses the claims of any token the worker parsed, verified or not (valid,
expired, bad signature): a match can only deny. Gaps:

- A request that carries **no token** is anonymous in attribute mode and is not
  matched (P2 require mode closes this).
- A token whose key cannot be checked (`unverified`, `jwks_unavailable`: a cold
  key cache, or a kid absent from the cache while the IdP is unreachable)
  carries no claims and is not matched, the same as no token.
- With `identity` mode off the worker parses no token, so there are no claims to
  match: the block list needs attribute mode.
- In transparent mode there is no `CONNECT` and no `Proxy-Authorization`, so the
  `CONNECT` check cannot run; only requests carrying `X-Warden-Identity` on
  terminated traffic are matched.
- Every policy update also resets rate-limit windows, so each block or unblock
  resets them on every worker.
- Sessions that are already open are cut at their next request; a user who is
  blocked is cut at once (see [Block list](#block-list)).

### Deployment and rollout

Workers need egress to the issuer. `deploy/k8s/networkpolicy.yaml` carries an
issuer egress rule whose address is an **operator-set value** (replace the
documentation address); the compose templates note which network reaches it
(`egress` for a public issuer, `cp-net` for one on the compose network).

Roll out **control plane first**: upgrade the control plane so it accepts and serves
the `identity` block, then upgrade workers, then set `identity.defaultMode` or a
per-agent `identity` value. Workers on an older build ignore the block, and a worker
on this build with no block stays off, so every step is safe to pause at.

## Block list

An admin blocks a person by Dex `sub` or email. The list ships to workers on the
policy wire as `blockedUsers`; a worker denies any request whose identity claims
match with `403 {"error":"user_blocked"}` and a deny event with reason
`user_blocked`. Matching uses the claims of any token the worker parsed, verified
or not (an expired or bad-signature token still names its user), because a match
can only deny.

### Open sessions are cut

A request that **arrived** under the old policy completes under it. A **session**
that the new list matches is **cut when the change is applied**, not drained:

- a raw CONNECT tunnel, an HTTP/2 connection and a WebSocket are closed at once,
  and the close interrupts active streams, not only new ones;
- an idle HTTP/1 keep-alive connection is closed without another request;
- an HTTP/1 connection that is mid-request finishes that request, delivers its
  full response, and is then closed. An HTTP/1 streaming response (for example
  SSE) that began before the block runs to its end; the same stream over h2, a
  tunnel or a WebSocket is cut at once.

After each applied policy change the worker closes the matching sessions and
writes **one** `user_blocked` deny event per closed session (its protocol, domain
and the user's sub). Sessions with no identity are not tracked, so anonymous
traffic pays nothing. Two metrics report it, neither labelled with identity:
`warden_blocklist_entries` (users on the list after the last applied change) and
`warden_blocklist_sessions_closed_total`.

### How fast a block applies

`BlockStore.Add` refreshes the served policy, which wakes held long-polls at
once, so a connected worker applies a block within about 1 s. The offline CLI
(`warden control-plane block add --state-dir`) adds at most one 2 s `data_version`
poll. A worker backing off after control-plane errors applies it after at most the
15 s backoff plus one long-poll round trip; `controlPlane.longPollWait` (default
30 s) does not delay a changed policy.

### Known gaps

- **No token, no match.** In identity `attribute` mode a request or session that
  carries no token at all has no claims to match and is not blocked. P2 `require`
  mode closes this gap.
- **Identity off.** With identity mode off the worker parses no token, so nothing
  is matched; turn identity on (`attribute`) for the block list to bite.
- **Transparent mode.** There is no CONNECT, so only an `X-Warden-Identity` header
  on terminated traffic identifies a user; a transparent connection is tracked
  only once such a header resolves.
- **Rate limits restart.** Every policy replace resets the rate-limit windows, so a
  block change resets them fleet-wide.

### Degraded modes

- **Control plane unreachable:** a worker keeps its last list and never unblocks
  on its own; new blocks apply when it reconnects.
- **Dex down:** admins cannot sign in to the console; use break-glass to block or
  unblock.
- **No `--state-dir`:** the control plane has no block-list store, so the
  block-list API answers 503 `state_dir_required` and `/policy` is unchanged.

## What's deliberately not here (yet)

The control plane's policy source is a YAML file it re-reads per request (or,
with `--policy-store=versioned`, the versioned store above), and the
fleet analytics store is in-memory (lost on restart). A database (persistent fleet
analytics), per-user SSO/RBAC policy editing (today one shared token), and per-agent (not just per-worker)
slicing are future work — and because the worker↔control-plane contract is just
HTTP, adding them doesn't change the workers.
