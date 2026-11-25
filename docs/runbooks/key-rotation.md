# Runbook: control plane signing key rotation

The control plane's `token` key signs Warden tokens, its `bundle` key signs
policy bundles, and its `ca` purpose holds the imported worker CA key. Token
keys rotate on a schedule or by hand; bundle keys rotate only through a staged
rollout, because every worker pins them; the `ca` key is imported, never
rotated. Reference: [Signing keys](../control-plane.md#signing-keys-keys). The
drills here are the command sequences that `go test ./cmd/proxy -run
'TestKeysRotateCLI|TestKeysRotateEmergency'`, `go test ./cmd/proxy -run
TestKeysRestoreHint` and `go test -tags integration ./test/integration -run
TestKeysRotationDrill` run, plus the harness scenario `go test
./test/scenarios -run 'TestScenarios/keys_cli_rotates_and_resets' -race`.

`warden control-plane keys` works on the state dir with the control plane
stopped or running: writes go through the same metadata store the running
control plane polls, so it picks a rotation up within about 2 seconds, with no
restart. `reset` is the one command that refuses while a control plane holds
the state-dir lock, because deleting keys under a live signer is never wanted.

## 1. The key set and the CLI

Each key has a kid (the RFC 7638 thumbprint of its public key) and a state:
`active` signs now, `next` is published ahead of its first signature,
`retired` no longer signs but stays in the JWKS for its overlap window,
`revoked` left the JWKS at once (an emergency), `destroyed` is history — a row
with no key. Private material lives only in PKCS#8 PEM files at
`<state-dir>/keys/<purpose>/<kid>.pem` (directories 0700, files 0600); the
database, the JWKS, `keys list` and the audit rows hold public data only.

```sh
# What the state dir holds: one row per key, metadata only.
warden control-plane keys list --state-dir /var/lib/warden-cp
warden control-plane keys list --state-dir /var/lib/warden-cp --purpose token --json

# The published key set as a JWKS — what /.well-known/jwks.json serves.
warden control-plane keys list --state-dir /var/lib/warden-cp --jwks

# One key's public JWK instead of the whole set.
warden control-plane keys export --purpose bundle --state active --state-dir /var/lib/warden-cp
```

| Command | Flags | Meaning |
|---|---|---|
| `keys list` | `--purpose`, `--jwks`, `--json` | The rows (public metadata) or the published JWKS. Opens the database read-only. |
| `keys rotate` | `--purpose token`, `--emergency`, `--yes`, `--admin-audit-key-file` | Promote `next`, retire (or, with `--emergency`, revoke) the old active, publish a fresh `next`. |
| `keys rotate --purpose bundle` | `--stage`, `--activate`, `--force`, `--emergency --yes`, `--admin-url`, `--api-key-file`, `--ca-cert` | The staged bundle rotation of [section 6](#6-staged-bundle-rotation): `--stage` signs with both keys, `--activate` makes the next key the only signer behind the workers' pins. |
| `keys export` | `--purpose`, `--state next\|active` | Public JWK only. Without `--state`: the JWKS of the published keys (active, next, and a retired key during its overlap) — what `controlPlane.bundleKeysFile` takes. |
| `keys reset` | `--purpose`, `--yes`, `--admin-audit-key-file` | Delete every key of the purpose — files and rows — and regenerate `token`/`bundle` from scratch. |

All four take a required `--state-dir` and an optional `--config` naming the
file that carries the `keys:` block (without it the keys defaults apply). No
output ever contains private material: no `d` JWK member, no PEM block.

Exit codes, so a drill script can tell the outcomes apart:

| Code | Meaning |
|---|---|
| 0 | Applied. |
| 1 | Nothing changed — a refusal: no or too-young `next` key, a bundle rotation without `--stage` or `--activate`, an `--activate` the pin gate refused, or `reset` while the control plane holds the state-dir lock. A reset that partially applied also exits 1: its rows are gone and its audit row has outcome `error` with the removed count. |
| 2 | Usage error: a bad flag, a missing or unopenable state dir or audit key, a missing `--yes` or a declined confirmation, or `rotate --purpose ca`. |
| 3 | A stood rotation: the promotion committed, so the old key is out of the signing slot — revoked under `--emergency`, retired otherwise — and only the fresh `next` key is missing. |

When the state dir has an admin audit chain, each `rotate` and `reset` appends
one row (`keys.rotate_requested`, `keys.reset`; `auth_method` `cli`, actor
`cli:<os user>`) and the transitions the request causes carry the same actor.
With no audit table the command logs one line instead; with rows present and
the audit key missing or mismatched it refuses and changes nothing. The
console's **Keys** tab offers the same rotation for the `token` purpose through
`POST /dashboard/api/keys/rotate` (never for `bundle`); the CLI is the offline
path that also works with the control plane down. The bundle steps write the
same action with an `op` detail (`stage`, `activate`, `emergency_activate`).

## 2. Scheduled token rotation

With `keys.enabled: true` and `keys.token.rotationInterval` set (default
`720h`), the control plane rotates the token key by itself: it promotes the
published `next` once `keys.token.prepublish` (default `1h`, minimum `10m`)
has passed since the key was published — so verifiers already hold it —
retires the old key (its private material is deleted at once) and publishes a
fresh `next`. `keys.token.overlap` (default `48h`, minimum `20m`) keeps the
retired key in the JWKS so tokens it signed keep verifying, after which its row
is destroyed. `rotationInterval: 0` means hands off: rotate only with the CLI.
The `bundle` purpose must stay `0`.

An active token key older than twice its interval raises a `key_overdue`
finding; a rotation that fails keeps the current key and raises
`key_rotation_failed`. Both reach the `integrations` routes and
`GET /dashboard/api/keys` shows per-purpose `loaded` and `lastError`.

## 3. Manual token rotation

```sh
warden control-plane keys rotate --purpose token \
  --state-dir /var/lib/warden-cp --config /etc/warden/config.yaml
```

The command exits 0 with `rotation complete: <kid> now signs with ...; the
previous key stays published for its overlap window`, naming the promoted kid.
It refuses — exits non-zero, changes nothing — when the purpose has no `next`
key, or when the `next` key was published less than `keys.token.prepublish`
ago: the error names the remaining wait. That floor is what makes rotation
safe, so plan the prepublish window into the drill instead of bypassing it.

## 4. Emergency rotation

When the token key may be compromised, rotate it out at once:

```sh
warden control-plane keys rotate --purpose token --emergency --yes \
  --state-dir /var/lib/warden-cp --config /etc/warden/config.yaml
```

- The current active key is **revoked**: it leaves `/.well-known/jwks.json`
  immediately and its private material is deleted. The revocation and the
  promotion of the published `next` commit as one transaction, so no observer
  ever sees the purpose without a signing key; a fresh `next` is published
  after, and if that write fails the rotation still stands — the empty slot is
  refilled by the next scheduler pass. With no `next` key at all the emergency
  still revokes, and a fresh key is generated straight into the vacant slot:
  fail closed — no signing at all is preferred to signing with a leaked key.
  Both failures exit **3**, not 1, and say so in their own line before the
  error: the compromised key **is** revoked, and the error names only what is
  still missing.
- **In-flight tokens die with it.** Tokens signed by the revoked kid stop
  verifying as soon as workers refresh their key set — workers poll the
  control plane's data version and pick a change up within about 2 seconds —
  so every holder is refused on their next request and must sign in again.
  That is the point of the flag; do not use it for a routine rotation.
- **Revoke the sessions too.** A rotation kills the keys, not the sessions:
  revoke the affected users' token sessions through the token-session revoke
  routes (W-P2-TOKX-07, admin-only and audited) so the token service refuses
  further exchanges for them; tokens already issued still expire within their
  TTL.
- `--emergency` on a non-interactive stdin (a script, CI) also requires
  `--yes`; without it the command exits non-zero and changes nothing. On a
  terminal it asks for confirmation instead. One audit row is appended either
  way — with outcome `error` when the rotation stood, none at all for a
  refusal.

## 5. Checking propagation

After any rotation, from a machine that can reach the control plane:

```sh
curl -s http://cp.example.internal:7070/.well-known/jwks.json | jq -r '.keys[].kid'
curl -s -o /dev/null -w '%{http_code}\n' http://cp.example.internal:7070/readyz
```

The JWKS must list the new active kid — and, after a non-emergency rotation,
the retired one until `keys.token.overlap` passes; after an emergency it must
not list the revoked kid at all. `/readyz` answers `200 ok` while every enabled
purpose has a loaded active key and `503 {"keys":"no_active_key"}` when one
does not. The console's key view, `GET /dashboard/api/keys` (admin), shows the
same set with each key's state and timestamps; use it to confirm from the fleet
side that what the control plane serves is what you expect.

## 6. Staged bundle rotation

Workers do not fetch bundle keys live: each worker pins them —
`controlPlane.bundleKeys` or `controlPlane.bundleKeysFile` — and refuses a
bundle that no pinned key signed. So a bundle key never rotates on a schedule
(`keys.bundle.rotationInterval` must be `0`; the scheduler never touches the
purpose) and never in one step. The drill is
`go test ./cmd/proxy -run 'TestKeysRotateBundle'`, `go test ./internal/controlplane
-run TestBundleStagedRotation` and the harness scenario `go test ./test/scenarios
-run 'TestScenarios/bundles_key_rotation_staged' -race`.

The rule behind every step: **a worker accepts only what a key it pins signed.**
The control plane never makes that weaker — a step either adds a signature
(`--stage`) or stops adding one only after the workers report they hold the
replacement (`--activate`).

### Rollout order, first time

1. **`--bundles=offer`.** Start the control plane with `--bundles=offer`
   (needs `--state-dir`, `--policy-store=versioned`, `keys.enabled`). Workers
   without pins keep the unsigned wire; nothing changes for them.
2. **Pin every worker.** Export the public keys and put them on each worker as
   `controlPlane.bundleKeysFile` (or inline `bundleKeys`), then roll the workers:

   ```sh
   warden control-plane keys export --purpose bundle --state-dir /var/lib/warden-cp \
     > bundle-keys.json
   ```

   The file is public keys only (no `d` member) and is exactly what the worker's
   loader takes. The compose recipe does this for you:
   `docker compose -f deploy/compose/docker-compose.control-plane.yml -f
   deploy/compose/docker-compose.bundles.yml up` exports the JWKS into a volume
   and starts each worker pinned to it. Watch the fleet view: a pinned worker
   shows its bundle seq and `pinnedKids`, and the `bundle/v1` capability.
3. **`--bundles=require`.** Once the fleet view shows no worker without
   `bundle/v1`, restart the control plane with `--bundles=require`: a request
   without the bundle `Accept` header now gets `406 signed_bundle_required`.

### Staged rotation (routine)

Pick a quiet moment; the whole sequence takes a prepublish window
(`keys.bundle.prepublish`, default `1h`) plus the time to roll your workers.

1. **Export and pin the next key.** The next key already exists (created with the
   purpose; `--stage` creates it if it is missing). Re-export — the output now
   lists the active and the next kid — and roll the new pin file onto every
   worker. A worker pinning both keys verifies bundles across the whole rotation.
   `keys export --purpose bundle --state next` prints just the next key's JWK.
2. **Stage.**

   ```sh
   warden control-plane keys rotate --purpose bundle --stage --state-dir /var/lib/warden-cp
   ```

   Within about 2 seconds the control plane signs every envelope with **both**
   keys (`bundle signed … kids=[active, next]` in its log). A worker pinned only
   to the old key and a worker pinned only to the new one both accept every
   envelope, at the same seq. Staging restarts the next key's `publish_at`, so the
   prepublish window counts from the moment both signatures were served. It is
   idempotent; a CP restart keeps it (the stage is in the database).
3. **Wait for the pins.** Until every online worker reports the next kid in
   `pinnedKids` (the fleet view, or `GET /dashboard/api/workers`) and the
   prepublish window has passed.
4. **Activate.**

   ```sh
   warden control-plane keys rotate --purpose bundle --activate \
     --state-dir /var/lib/warden-cp \
     --admin-url https://cp.example.internal:7070 --api-key-file /etc/warden/rotate.key
   ```

   The worker pins live in the running control plane's memory, so the command
   reads them through its admin API: `--admin-url` plus a `wak_` API key with
   the `traffic:read` scope in `--api-key-file` (or `$WARDEN_API_KEY`;
   `--ca-cert` adds a CA for a private TLS certificate). It **refuses**, naming
   the proxy ids, unless every online worker that verifies bundles reports the
   next kid; a worker that has not pinned it would reject every bundle the moment
   the old key stops signing. It also refuses when it cannot read the pins at all
   (fail closed), when the key was not staged, and inside the prepublish window.
   When it succeeds the next key is the only signer and the old key is **retired**:
   its private material is deleted, its public key stays in the exported set for
   `keys.bundle.overlap` (default `48h`). Offline workers that do not report the
   kid do not block, but the command warns and names them: they will reject
   bundles until pinned.
5. **Drop the old pin — later.** Leave the old key pinned until the overlap has
   passed *and* every worker has applied a bundle signed by the new key.
   A restarting worker with a last-known-good cache verifies that cache under the
   pins it holds (the cache keeps every signature of the envelope it saved, so
   either key verifies a dual-signed one). A worker whose cache only the old key
   signed and that already dropped the old pin has no floor to boot from: it
   fetches from the control plane, and fails closed if that is down. After the
   overlap, `keys export` no longer lists the old key; re-export and roll that
   pin file.

`--force` overrides the pin check — for a worker you know is gone, or a control
plane whose admin API you cannot reach. It still needs the stage and the
prepublish window. It writes **one** audit row (`keys.rotate_requested`,
`op=activate`, `forced=true`) carrying the missing proxy ids, or
`pins_unverified=true` when the pins could not be read. Using it on a worker that
is merely behind strands that worker: it rejects every bundle (`unknown_kid`)
and keeps enforcing its last-known-good policy until that bundle expires, then
fails closed or open per `controlPlane.bundleExpiry`.

Every step writes an admin audit row (`op=stage`, `op=activate`) naming the kids
and logs them; the transitions it causes (`keys.staged`, `keys.activated`,
`keys.retired`) carry the same actor.

### While the bundle publisher is degraded after a token rotation

Scheduled **token** rotation interacts with signed bundles. A new token key may
mint only once the last-served bundle carries it in its token JWKS. If the
bundle publisher is degraded when a scheduled token rotation promotes the new
key (`/healthz` answers `degraded: bundle signing failed`, the log says `bundle
sign failed`), the mint guard refuses the new key and the token service answers
`503 signer_unavailable` until the next successful sign. Fix the signing failure
(a bundle key the control plane cannot load, a store outage); minting resumes by
itself on the next sign. Nothing is lost — the old key stays valid for its
overlap — but plan token rotations for a time the bundle key is healthy.

### Emergency rotation after a compromise

When the **bundle** key may be compromised, whoever holds it can sign a policy
every worker that pins it would apply: replacing the key is urgent, and so is
telling the workers to stop trusting it.

1. `keys rotate --purpose bundle --stage` first: the control plane signs with both
   keys at once, so a worker you re-pin to the next key alone keeps verifying
   while the compromised key still signs.
2. `keys export --purpose bundle --state next` and pin the next key on every
   worker **in place of** the compromised one (a pin file with the next key
   only), then roll the workers. A worker that no longer pins the old key rejects
   anything it signed (`unknown_kid`).
3. `warden control-plane keys rotate --purpose bundle --activate --emergency --yes --state-dir /var/lib/warden-cp`
   promotes the next key at once — no prepublish window — and **revokes** the
   old one: it leaves the exported set immediately and its material is deleted.
   The pin check still applies (a worker that does not pin the next key is cut
   off); `--force` overrides it, knowing what it costs.
4. Rotate the **token** key too if it shared a host with the bundle key
   (section 4), and check the fleet: every worker must report only the new kid
   in `pinnedKids` and no `lastRejectReason`.

The window between a compromise and step 3 is the exposure: a worker that still
pins the old key trusts it, and a signed bundle replayed within its lifetime
(`--bundle-max-age`, default 24h) stays valid there. A restarted worker's cache
is verified under its pins like any bundle, so a cache the compromised key
signed is refused once the old pin is gone.

### After a restore: `--bundle-seq-floor`

Pinned workers refuse a bundle with a lower seq than the one they hold
(`rollback`), and a restored control plane's publish log is behind them. Before
the first start after a restore, read the highest `bundleSeq` the fleet view
reports and start the control plane with `--bundle-seq-floor` **above** it:

```sh
warden control-plane --state-dir /var/lib/warden-cp --policy-store=versioned --bundles=offer --bundle-seq-floor 5000
```

It appends one `restore` row at that seq when the log is lower, so the next
bundle is newer than anything a worker holds. A restore also loses the key
directory (section 7): if the key material is gone, `keys reset --purpose bundle`
creates new keys, and the workers must then be re-pinned to them — treat it as
a rotation without the overlap, with every worker rejecting bundles until its
pins move. A worker with a last-known-good cache refuses the restored control
plane's lower seq only until that cached bundle expires.

## 7. After a restore: reset

A backup set holds `warden-cp.db` — public metadata — and never the key
directory: the manifest lists it under `not_included` (`signing key
material`, alongside `cp-audit.key`). Restoring into a directory without
`<state-dir>/keys` therefore leaves every `next`/`active` row without
material. `warden control-plane restore` names the key directory it checked
(`<state-dir>/keys` — restore takes no `--config`) and, per purpose, that its
material is not there; verify the directory holds the key files first (the
store may simply live elsewhere), and reach for the reset hint only when the
material is truly lost. The control plane still starts (the store-unavailable
behaviour in [control-plane.md](../control-plane.md#signing-keys-keys)) but
signing fails and a `signing_key_unavailable` finding is raised until the keys
are regenerated. The drill is `go test ./cmd/proxy -run TestKeysRestoreHint`.

Regenerate with the control plane stopped:

```sh
warden control-plane keys reset --purpose token --yes \
  --state-dir /var/lib/warden-cp --config /etc/warden/config.yaml
warden control-plane keys reset --purpose bundle --yes \
  --state-dir /var/lib/warden-cp --config /etc/warden/config.yaml
```

`removed 2 token key(s); token now signs with fresh key <kid>`: the old rows
and files are gone, a fresh active and `next` are created, and the purposes
sign again on the next start. Every token and bundle signed before the loss
stops verifying — the kids left the published set with their rows — which is
the honest outcome: key material that was on the lost disk must not come back.
`keys reset` refuses while the control plane holds the state-dir lock
(`control plane is running; stop it before resetting its signing keys`), so
stop the control plane first.

The `ca` purpose is different: nothing regenerates it.
`warden control-plane keys reset --purpose ca --yes` clears the CA row and its
material; import a fresh worker CA key when ready
([control-plane.md](../control-plane.md)).

A `reset` is a last resort, not a rotation: it is for a restore that lost the
key store, or a compromise where even the retired keys must go. After a bundle
`reset` every pinned worker rejects bundles until it pins the new key (section
6). For everything else there are sections 2 to 6.
