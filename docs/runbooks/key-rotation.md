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
| `keys export` | `--purpose`, `--state next\|active` | Public JWK only. Without `--state`: the JWKS of active + next. |
| `keys reset` | `--purpose`, `--yes`, `--admin-audit-key-file` | Delete every key of the purpose — files and rows — and regenerate `token`/`bundle` from scratch. |

All four take a required `--state-dir` and an optional `--config` naming the
file that carries the `keys:` block (without it the keys defaults apply). No
output ever contains private material: no `d` JWK member, no PEM block.

When the state dir has an admin audit chain, each `rotate` and `reset` appends
one row (`keys.rotate_requested`, `keys.reset`; `auth_method` `cli`, actor
`cli:<os user>`) and the transitions the request causes carry the same actor.
With no audit table the command logs one line instead; with rows present and
the audit key missing or mismatched it refuses and changes nothing. The
console's **Keys** tab offers the same rotation for the `token` purpose through
`POST /dashboard/api/keys/rotate` (never for `bundle`); the CLI is the offline
path that also works with the control plane down.

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
  immediately and its private material is deleted. The published `next` is
  promoted and a fresh `next` appears, so the control plane keeps signing.
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
  way — the refusal appends none.

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
`controlPlane.bundleKeys` or `controlPlane.bundleKeysFile` — and refuses
bundles it cannot verify. A bundle key rotation is therefore a staged rollout,
never a behind-the-back swap:

1. **Export** the JWKS the workers will pin. The export is public keys only,
   so it can be copied into configs and repos:
   `warden control-plane keys export --purpose bundle --state-dir /var/lib/warden-cp`
   prints the JWKS of active + next — exactly what
   `controlPlane.bundleKeysFile` takes. One key instead:
   add `--state next`.
2. **Pin it on every worker** and roll them. A worker that now holds both the
   active and the next bundle key verifies bundles across the whole rotation.
3. **Wait for the pin.** Watch the workers' heartbeats until every one of them
   reports the next kid pinned.
4. **Stage, then activate** with the staged rotation commands of
   W-P2-SBND-07: `keys rotate --purpose bundle --stage` marks the pinned key
   ready without touching the serving key, and `--activate` promotes it once
   the pin is visible fleet-wide.

Until W-P2-SBND-07 lands, the CLI only ever refuses a bundle rotation —
`warden control-plane keys rotate --purpose bundle` exits non-zero and prints
the next kid to pin and a pointer to this runbook. Nothing is changed. That is
the guardrail: bundle keys move only when every worker already holds the key
they are about to be asked to trust.

## 7. After a restore: reset

A backup set holds `warden-cp.db` — public metadata — and never the key
directory: the manifest lists it under `not_included` (`signing key
material`, alongside `cp-audit.key`). Restoring into a directory without
`<state-dir>/keys` therefore leaves every `next`/`active` row without
material. `warden control-plane restore` says so, per purpose, and prints the
reset hint; the control plane still starts (the store-unavailable behaviour in
[control-plane.md](../control-plane.md#signing-keys-keys)) but signing fails
and a `signing_key_unavailable` finding is raised until the keys are
regenerated. The drill is `go test ./cmd/proxy -run TestKeysRestoreHint`.

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
key store, or a compromise where even the retired keys must go. For everything
else there are sections 2 to 6.
