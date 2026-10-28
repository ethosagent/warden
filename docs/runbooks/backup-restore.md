# Runbook: control plane backups and restore

The control plane can write consistent backup sets of its SQLite state and its
served config on a schedule, and `warden control-plane restore` loads one back
after checking it. Backups are **off by default**. Reference: [Scheduled
backups](../control-plane.md#scheduled-backups---backup-dir). The restore drill
here is the command sequence that `go test ./cmd/proxy -run
TestControlPlaneRestore_RoundTrip` runs.

## 1. Turn backups on

Backups need `--state-dir`. The backup directory must be a different directory
that is not inside the state dir.

| Flag | Default | Meaning |
|---|---|---|
| `--backup-dir` | empty (off) | Where sets are written. Must not equal or sit inside `--state-dir`. |
| `--backup-interval` | `24h` | Time from the newest complete set to the next run. Minimum `1h`. |
| `--backup-keep` | `7` | Complete sets kept. Minimum `1`. The newest is never pruned. |
| `--backup-include` | `cp,alerts,config` | What a set holds, from `cp`, `alerts`, `config`, `fleet`. `fleet` is opt-in. |

```sh
warden control-plane --config /etc/warden/config.yaml --state-dir /data \
  --backup-dir /backups --backup-interval 6h --backup-keep 14
```

A set is written at startup when none is newer than the interval, then every
`--backup-interval` after the newest set, so a control plane that restarts nightly
still backs up. A flag error names the flag (`--backup-dir requires --state-dir`,
`--backup-interval 30m is too short: the minimum is 1h`, and so on). In the compose
recipe the volume `cp-backups` is mounted at `/backups` and the flags are commented
in `deploy/compose/docker-compose.control-plane.yml`; uncomment them and give the
volume to the image user once (the comment shows the command).

### Set layout

Each set is a directory named for its UTC start time, `20060102T150405Z`:

```
/backups/
  20270115T080000Z/
    manifest.json        written last: a directory without it is not a complete set
    warden-cp.db         policy versions, worker tokens, block list, admin audit chain, sessions
    warden-alerts.db     alert store (with --backup-include alerts)
    warden-fleet.db      fleet analytics (only with --backup-include fleet)
    config.yaml          the served config, which drives the /policy ETag
  .tmp-20270116T080000Z/ a set being built, renamed into place when complete
```

Directories are mode 0700 and files 0600. Each database is copied consistently on
its own; the set is not one snapshot across the databases. A run needs 1.2 times
the source sizes free on the backup filesystem or it fails with `insufficient free
space` and writes nothing.

`manifest.json` fields: `format` (`warden.cp.backup.v1`), `warden_version`,
`schema_version`, `audit_key_fingerprint` (the admin audit key id, absent from an
offline backup), `created_at`, `finished_at` (UTC), `files` (`name`, `sha256`,
`size` each), `skipped` (a store that was not running, with a reason) and
`not_included`. The sha256 values check integrity, not authenticity: keep the sets
somewhere only you can write.

### Pruning

After each successful run the newest `--backup-keep` complete sets are kept and the
rest are removed, and `.tmp-` directories older than 24 hours are removed. Anything
else in the directory is left alone.

## 2. Take a set on demand

While the control plane runs, an admin starts a backup in the background:

```sh
curl -sS --cacert ca.pem -X POST -H "Authorization: Bearer $WARDEN_CP_ADMIN_TOKEN" \
  https://cp.example.internal:7070/dashboard/api/backup
# {"started":true}      (202; 409 backup_in_progress while one runs; 404 without --backup-dir)
```

That form is for `console.auth: none`, where dashboard writes use the admin bearer
(`--admin-token-env`). With `console.auth: oidc` the route needs an admin session
and its `X-Warden-CSRF` header, and the call is audited as `backup.run`. The
outcome is the scheduled runner's: a failure is logged and reported as a Finding,
not returned to the caller.

For a **stopped** control plane, the offline command writes one set in the same
layout:

```sh
warden control-plane backup --state-dir /data --backup-dir /backups \
  --backup-include cp,alerts,config
```

It prints the set path and exits 0, or prints the error and exits 1. It takes the
state-dir lock, so while a control plane runs it exits 1 with `control plane is
running; use POST /dashboard/api/backup or stop it`. It never prunes older sets and
never opens the admin audit store (so the manifest has no `audit_key_fingerprint`).
Use `--analytics-db` and `--alerts-db` when the control plane used non-default paths.

### The state-dir lock

With `--state-dir` the control plane holds an exclusive `flock` on
`<state-dir>/warden-cp.lock` for its whole life. That is what lets restore and the
offline backup refuse to run under a live control plane, and what stops two control
planes sharing one state dir. The kernel drops the lock when the process dies, so a
crash leaves nothing stale. **The state dir must be on a local filesystem.** `flock`
on NFS and similar network filesystems is not reliable, and a lock that does not
exclude is worse than none. Put `--state-dir` on a local disk or a block volume, and
put `--backup-dir` anywhere.

## 3. Get complete sets off the host

A backup on the same disk as the state dir does not survive that disk. Copy sets to
another host or bucket on a schedule shorter than your tolerance for loss. Copy only
**complete** sets: skip the `.tmp-*` directories (a set being built, or a failed run)
and check that `manifest.json` is present in what you copied.

```sh
rsync -a --exclude '.tmp-*' /backups/ backup-host:/srv/warden-cp-backups/
```

Pruning can remove an old set while you copy, so copy newest-first or copy after the
run finishes. Keep your own retention off host: `--backup-keep` only governs
`--backup-dir`.

## 4. What a set does not hold

Keep these separately; losing them is not recoverable from a set:

- `cp-audit.key` and the HMAC key beside it (`--admin-audit-key-file`). Back them up
  to a secret store, never with the sets. Restore refuses a set whose recorded key
  fingerprint does not match the key on the target.
- The Dex (identity provider) storage and configuration.
- The CA certificate and key (`--ca-cert`, `--ca-key`) the control plane mints its
  server certificate from.
- The secret backend and every secret value: env vars such as the
  `--admin-token-env` value, the break-glass hash, and the `wwt_` worker token
  plaintexts (the database holds only their hashes). The manifest lists
  `cp-audit.key`, `IdP storage` and `secret backend` under `not_included`.

## 5. Backup health

A backup that fails or goes quiet is not silent:

- A failed run logs ERROR `msg=cp_backup_failed` and publishes one `backup_failed`
  Finding (high; one per failing source, or `run`).
- With no success for twice `--backup-interval`, a `backup_stale` Finding (high).
  A success ends it.
- `GET /dashboard/api/setup` carries `backup` (`enabled`, `lastSuccessAt`,
  `lastError`, `lastSet`, `sizeBytes`) for admins, and the dashboard header shows a
  green or red badge from it. It is absent when `--backup-dir` is unset.
- Route both Findings to a channel: `integrations[].match[].rule: backup_failed`
  and `backup_stale` (see [break-glass](break-glass.md#1-prepare-it-before-the-incident)
  for the block).

## 6. Restore drill

Run this on a scratch host or a copy of the state volume first, then again for real.
Capture the policy ETag **before** the incident, so you have something to compare:

```sh
curl -sSI --cacert ca.pem -H "Authorization: Bearer $WARDEN_WORKER_TOKEN" \
  https://cp.example.internal:7070/policy | grep -i '^etag'
```

1. **Stop the control plane.** Restore takes the state-dir lock and refuses with
   `control plane is running; stop it before restoring` while one holds it.
2. **Restore a set.** Point `--from` at a complete set directory (the one holding
   `manifest.json`). Add `--force` when the state dir already holds files:

   ```sh
   warden control-plane restore --from /backups/20270115T080000Z --state-dir /data --force
   ```

   Optional flags: `--analytics-db` and `--alerts-db` (non-default database paths),
   `--admin-audit-key-file` (default `<state-dir>/cp-audit.key`) and
   `--new-audit-key` (accept a target key that differs from the backup's; the
   override is recorded in the audit row).
3. **Check the admin audit chain.** The chain must verify and end with exactly one
   `cp.restore` entry:

   ```sh
   warden control-plane admin-audit verify --state-dir /data
   ```

4. **Start the control plane** on the restored directory (the same command line as
   before). Workers reconnect on their own.
5. **Compare the `/policy` ETag** with the one you captured. It matches when the set
   was taken after the last policy change. If it differs, policy was edited after the
   set: see step 7.

In the compose recipe, steps 1, 2 and 4 are:

```sh
docker compose -f deploy/compose/docker-compose.control-plane.yml stop control-plane
docker compose -f deploy/compose/docker-compose.control-plane.yml run --rm --no-deps \
  control-plane control-plane restore --from /backups/20270115T080000Z --state-dir /data --force
docker compose -f deploy/compose/docker-compose.control-plane.yml up -d control-plane
```

### What restore checks before it touches anything

It stages every file next to its target and verifies there: the sha256 and size of
each file against `manifest.json` (`manifest mismatch: warden-cp.db` names the file),
SQLite `integrity_check` on each database, that the set's schema version is not newer
than this binary's, that a non-empty admin audit chain verifies, and that the target's
audit key fingerprint matches the manifest (`audit key fingerprint does not match the
backup`). A non-empty target is refused unless `--force` (`target state dir is not
empty; pass --force`). Only then does it swap: replaced databases, their `-wal` and
`-shm` files and the old `config.yaml` are moved into `<state-dir>/pre-restore-<ts>/`,
the staged files are renamed into place (mode 0600), stale write-ahead files are never
replayed, and the `sessions` and `oidc_pending` tables are emptied so every console
cookie issued before the backup stops working. Any failed check leaves the target
unchanged; a failure during the swap rolls back. One `cp.restore` row (target: the
sha256 of `manifest.json`, `auth_method` `cli`) is appended to the admin audit chain.
Exit codes: 0 restored, 1 refused or failed (the message names the reason), 2 usage
error. If the files are in place but the audit row failed, it exits 1 with `restore is
applied but unaudited`.

### 7. Re-apply what happened after the backup

A set is a point in time. Anything done after `created_at` is gone, and an old
snapshot can bring back **revoked access**. Restore prints the warning and the
timestamp. Re-apply, newest evidence first, from the shipped `admin_audit` JSON log
(the `warden.admin.v1` stream; see the [SIEM guide](../siem.md); the log is off host,
so it survived):

```sh
jq -c 'select(.schema=="warden.admin.v1" and .ts > "2027-01-15T08:00:00Z"
  and (.action|test("^(worker_token|blocked_users|policy)\\.")))' admin-audit.jsonl
```

- **Worker-token revocations** (`worker_token.revoke`, `target_ref` `token:<id>`):
  revoke again, one at a time, on the host that holds the state volume:
  `warden control-plane token revoke --id wt_... --state-dir /data` (the id is the
  `token:` value). Tokens created after the set (`worker_token.create`) do not exist
  any more: mint them again with `warden control-plane token create`.
- **User blocks** (`blocked_users.add`, `blocked_users.remove`): the row records that a
  block was added or removed, by whom and when, not who was blocked (it keeps only
  `has_sub` and `has_email` flags, no value). Take the people from your incident or
  change record, then `warden control-plane block add --state-dir /data --email ...
  --reason ...` and `block remove`.
- **Policy versions** (`policy.write`, `policy.rollback`): the rows hold hashes, not
  the policy. Re-apply from your source of truth (the YAML in version control) through
  the console or `warden policy import`, and confirm the ETag again.
- Also re-check anything else an admin changed in that window (`integrations`,
  `settings`) in the same log.

Order matters for safety: do the revocations and blocks **first**, before the
control plane serves workers again, or restore with the control plane's listener
firewalled until they are done.

## 8. Known limits

- A set is not one snapshot across databases; they share no foreign keys.
- Backups sit on the control plane's disk until you copy them off.
- One control plane per state dir; the lock needs a local filesystem. The backup job
  is for SQLite state and is disabled when the Postgres HA mode replaces it (not in P1).
- The control plane has no metrics endpoint in P1; the Findings, the ERROR log lines
  and the `/dashboard/api/setup` status are the signals.
