# Production readiness checklist (Phase 1)

Run through this before a control plane serves real traffic. Every row names the
exact flag or config key and a check you can run. Flag names are control-plane
flags (`warden control-plane --help`) unless a row says it is a worker flag
(`warden run --help`). Config keys are YAML paths in the file passed with `--config`
(the control plane reads its `console:` block from its own config; workers read their
own `controlPlane:`, `central:` and `identity:` blocks). A Go test
(`go test ./cmd/proxy -run TestProductionReadinessKeysExist`) fails when a flag or key
in backticks here does not exist.

Replace every example value (hosts, paths, ids). Secrets are only ever named by env
var, file or stdin: nothing here holds a real token or hash.

A control plane that satisfies sections 1 to 4 starts like this (paths and host names
are examples; the secrets come from the environment named by `--admin-token-env` and
from the files the config names):

```sh
warden control-plane --config /etc/warden/config.yaml --state-dir /var/lib/warden-cp \
  --listen 0.0.0.0:7070 --ca-cert /etc/warden/certs/proxy-ca.crt \
  --ca-key /etc/warden/certs/proxy-ca.key --tls-host cp.example.internal \
  --require-worker-tokens --admin-token-env WARDEN_CP_ADMIN_TOKEN \
  --require-console-auth --policy-store=versioned \
  --backup-dir /srv/warden-cp-backups --backup-interval 6h --backup-keep 14
```

## 1. Transport and worker authentication

| # | Item | Set | How to check |
|---|---|---|---|
| 1 | Control plane serves TLS | `--ca-cert` and `--ca-key` (a CA the control plane mints its server certificate from), `--tls-host` for the SANs workers dial | `curl --cacert ca.pem https://cp.example.internal:7070/policy -o /dev/null -w '%{http_code}\n'` answers `401` (TLS works, no credential sent). Startup line `control plane worker auth` has `tls=true`. |
| 2 | Workers trust that CA | worker `controlPlane.caCert` and `central.caCert` | Worker logs show policy pulls succeeding; the fleet view lists it online. |
| 3 | Strict worker auth | `--require-worker-tokens` | Startup line says `auth_mode=strict`. The shared token and anonymous callers get `401` on `/policy`, `/control/heartbeat` and `/central/ingest`. |
| 4 | No plain-text escape hatch | `--allow-insecure-worker-auth` **unset**, `--legacy-token-env` **unset** | The control plane refuses to start with strict mode otherwise, naming the flag. Startup line `legacy_token=false`. |
| 5 | One token per worker, bound to its id | `warden control-plane token create --name ... --proxy-id ... --state-dir ...`; worker `controlPlane.tokenEnv`, `central.tokenEnv`, `central.proxyID` | `GET /dashboard/api/workers` shows `authKind: token` for every worker and no `legacyRequests`. Revoke with `warden control-plane token revoke --id wt_... --state-dir ...`. |
| 6 | The control plane's own admin bearer | `--admin-token-env` naming an env var whose value differs from any worker token | Dashboard writes without it answer `401` or `403`. Without it, startup WARNs `dashboard writes use the shared worker token; set --admin-token-env`. |
| 7 | State dir on a local disk | `--state-dir` | The control plane holds `<state-dir>/warden-cp.lock`; do not put the dir on NFS (`flock` is not reliable there). |

Migration from the old shared `WARDEN_CP_TOKEN` is in
[control-plane.md](control-plane.md#migrating-from-warden_cp_token).

## 2. Console sign-in and roles

| # | Item | Set | How to check |
|---|---|---|---|
| 8 | OIDC console, not an open one | `console.auth` = `oidc`; `console.oidc.issuer` is an `https` URL; `console.oidc.clientSecretEnv` names an env var | `GET /dashboard/api/setup` (with a session) shows `"authMode":"oidc"`; no "Open console" banner; a request without a session gets `401`. |
| 9 | Refuse to start open | `--require-console-auth` | With `console.auth` `none` the control plane exits at startup. |
| 10 | Roles mapped to IdP groups | `console.roles.admin`, `console.roles.editor`, `console.roles.viewer` | Sign in as a user of each group; `GET /auth/me` returns the expected `role`. A user in no group gets no access. |
| 11 | Session lifetime | `console.session.idle`, `console.session.absolute` | Defaults are fine for most; shorten for high-risk consoles. |
| 12 | Secrets route needs an admin | (automatic with oidc) | `GET /central/secrets` without an admin session answers `401`/`403`; with `console.auth` `none` it takes the admin bearer. |

## 3. Admin audit and off-host anchoring

| # | Item | Set | How to check |
|---|---|---|---|
| 13 | Signed admin audit chain | `console.adminAudit.enabled` = `true` (needs `--state-dir`) | `warden control-plane admin-audit verify --state-dir /data` exits 0. Back up the key at `--admin-audit-key-file` (default `<state-dir>/cp-audit.key`) to a secret store; sets never hold it. |
| 14 | Machine-readable admin stream | `audit.jsonLog.enabled` = `true`, `audit.jsonLog.output`, `audit.jsonLog.path` (a path of its own for the control plane) | Lines with `"schema":"warden.admin.v1"` appear. The control plane writes admin lines only when `console.adminAudit.enabled` is also true. |
| 15 | Shipped off host | a log collector reading that stream, as in [siem.md](siem.md) | The newest line is minutes old on the collector. A checkpoint line (`admin_audit.checkpoint`) arrives at startup, every 5 minutes and at shutdown. |
| 16 | Anchored verification | keep a recent `chain_seq` and `entry_hash` off host | `warden control-plane admin-audit verify --state-dir /data --anchor <chain_seq>:<entry_hash>` exits 0. Deleting the newest rows passes a plain verify but fails against an anchor. |

The worker side of the same stream (`warden.decision.v1`) uses the same
`audit.jsonLog` block in the worker's own config.

## 4. Backups and restore

| # | Item | Set | How to check |
|---|---|---|---|
| 17 | Scheduled backups | `--backup-dir` (outside `--state-dir`), `--backup-interval`, `--backup-keep` | `GET /dashboard/api/setup` shows `backup.lastSuccessAt`; a set directory with `manifest.json` exists. |
| 18 | An off-host copy | copy complete sets (skip `.tmp-*`) elsewhere | The off-host listing has the newest set. |
| 19 | The restore drill has been run | [runbooks/backup-restore.md](runbooks/backup-restore.md) | You have timed it once, on a copy, and re-applied revocations after it. |
| 20 | Backup alerts routed | an `integrations` entry whose `match` has `rule: backup_failed` and `rule: backup_stale` | Stop the backup target and confirm the Finding reaches the channel. |

## 5. Break-glass

| # | Item | Set | How to check |
|---|---|---|---|
| 21 | Disabled, or enabled with care | `console.breakGlass.enabled` = `false` (the default), or `true` with the rows below | Disabled: `POST /auth/breakglass` answers `404`. |
| 22 | The hash is not in the config | `console.breakGlass.passwordHashFile` or `console.breakGlass.passwordHashEnv` (exactly one), made with `warden control-plane hash-password --stdin` | `grep argon2id config.yaml` finds nothing. |
| 23 | Rotated after use | replace the file or env value; `console.breakGlass.sessionTTL` at most `4h` | The runbook's "after the incident" steps are done. |
| 24 | TLS | `--ca-cert` and `--ca-key`, or `console.breakGlass.allowBehindTLSTerminator` = `true` behind a proxy | The control plane refuses plain HTTP on a non-loopback `--listen` otherwise. |
| 25 | An alert route for `breakglass_login` | `rule: breakglass_login` in an `integrations` `match`, and `console.adminAudit.enabled` | No startup WARN about "no integration's alerts.match routes a critical breakglass_login Finding". |
| 26 | The Dex-down drill | [runbooks/break-glass.md](runbooks/break-glass.md) | `go test ./cmd/proxy -run TestControlPlaneBreakGlassDegraded` and `make e2e-identity-scenario NAME=TestBreakGlassDexDown` pass. |

## 6. Policy and users

| # | Item | Set | How to check |
|---|---|---|---|
| 27 | Versioned policy store | `--policy-store=versioned` (needs `--state-dir`; the default is still `file` in P1) | `GET /dashboard/api/policy/versions` lists versions; a rollback is one admin action. |
| 28 | Identity mode on, so users can be told apart | worker `identity.defaultMode` = `attribute`, `identity.issuer`, `identity.audience` | `warden identity status` shows claims; deny events carry the user. |
| 29 | Block list reaches every worker | admin API or `warden control-plane block add --state-dir ...` | Block a test user; the worker answers `403 {"error":"user_blocked"}` within seconds. |
| 30 | Workers advertise `blocklist/v1` | (automatic in this release) | `GET /dashboard/api/workers` lists `caps` per worker. A worker without `blocklist/v1` would silently ignore the block list; the dashboard does not render a badge for it yet, so check the field. |

### Identity and group policy: how they fail

- **Identity off means nothing is matched.** With `identity.defaultMode` off, a worker
  parses no token, so the block list matches nobody. Turn on `attribute` mode for the
  block list to bite.
- **No token, no match.** In `attribute` mode a request with no token has no claims
  and is not blocked. P2's `require` mode closes that gap.
- **Group-scoped allow entries fail closed.** An allow entry with `groups` or `users`
  is enforced with the verified subject: it never allows an anonymous request and a
  non-member is denied outright (never handed to the judge). With identity off or no
  token, a scoped entry therefore allows nothing. Entries without `groups` or `users`
  stay global.

## 7. Signing keys

| # | Item | Set | How to check |
|---|---|---|---|
| 31 | Keys on, with a rotation cadence | `keys.enabled` = `true` (needs `--state-dir`), `keys.token.rotationInterval` = `720h`, `keys.token.prepublish` = `1h`, `keys.token.overlap` = `48h` | `warden control-plane keys list --state-dir /data --purpose token` shows an `active` and a `next` key; `GET /.well-known/jwks.json` lists both kids. |
| 32 | The rotation drill has been run | [runbooks/key-rotation.md](runbooks/key-rotation.md) | `go test ./cmd/proxy -run 'TestKeysRotateCLI\|TestKeysRotateEmergency'` and `go test -tags integration ./test/integration -run TestKeysRotationDrill` pass. You have rotated once, on a copy, and watched the retired kid verify through its overlap. |
| 33 | Keys survive a restore | the manifest's `not_included` names the key store, so a restore needs `warden control-plane keys reset --purpose token --yes` and the same for `bundle` | `go test ./cmd/proxy -run TestKeysRestoreHint` passes: the restore prints the reset hint when material is missing, and the reset regenerates. |
| 34 | Key changes are audited | `console.adminAudit.enabled` = `true` | After a CLI rotation, `keys.rotate_requested` rows with `auth_method` `cli` appear in the admin audit (section 3). |

## 8. Known limits in Phase 1

- **One control plane per state dir.** The lock stops a second instance. There is no
  HA and no failover; restore from a set is the recovery path.
- **Break-glass limits are in memory** and reset on restart; there is one shared
  break-glass account.
- **No metrics endpoint** on the control plane. Findings, ERROR log lines and
  `GET /dashboard/api/setup` are the signals.
- **Restore is point in time.** Revocations, blocks and policy versions made after a
  set must be re-applied from the shipped admin audit log.
- **A token is bound to one proxy id**, compared exactly, with at most two active per
  id. Autoscaled pools without stable ids wait for P2.
- **The admin audit chain can lose its newest rows** if someone with write access to
  the state dir deletes them; only an off-host anchor catches that.
- **Backups share the disk** of the state dir until you copy them off host.

Related: [break-glass runbook](runbooks/break-glass.md),
[backup and restore runbook](runbooks/backup-restore.md),
[key rotation runbook](runbooks/key-rotation.md),
[admin audit key runbook](runbooks/admin-audit-key.md), [SIEM guide](siem.md),
[control plane reference](control-plane.md).
