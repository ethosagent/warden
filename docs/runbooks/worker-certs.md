# Runbook: worker certificates

Operating the worker CA and the short-lived mTLS client certificates workers use
toward the control plane. Background and the wire details are in
[Worker CA](../control-plane.md#worker-ca-workerca); moving a deployment off
per-worker `wwt_` tokens is [Migrating from per-worker
tokens](../control-plane.md#migrating-from-per-worker-tokens).

In every command below `D` is the control plane's `--state-dir` (`/data` in the
compose recipe), and `--config F` is the control plane's `--config` file (it carries
the `workerCA:` block, so the enrollment lifetimes apply).

## What you operate

- The **worker CA**: a root (offline) and an intermediate the control plane signs
  with. The control plane pins the intermediate chain (`workerCA.certFile`) and
  trusts nothing else for worker certificates. It is a separate trust root from the
  proxy CA (`--ca-cert`): never point one at the other.
- **Enrollment tokens** (`wet_...`): one-time (or prefix-bound, multi-use)
  credentials a worker trades for its first certificate.
- **Worker certificates**: 24h by default (`workerCA.certTTL`), renewed by the worker
  at about 50% of their life, kept under the worker's `controlPlane.stateDir`
  (`<stateDir>/cert/worker-cert.pem` and `worker-key.pem`, the key mode 0600).

## Enroll a worker

1. Mint a token for the worker id (printed once; it is good for one enrollment, for
   `workerCA.enrollTokenTTL`, 1h by default):

   ```sh
   warden control-plane enroll-token create --name worker-3 --worker-id worker-3 \
     --config F --state-dir D --out ./worker-3.enroll
   ```

   `--from-env VAR` registers a value you generated instead (compose and Kubernetes
   Secrets), and re-running with the same name, value and binding is a no-op. Admins
   can also use the console's "Worker enrollment tokens" panel or `POST
   /dashboard/api/worker-enrollments`.
2. Give the worker the token in the environment variable its config names, and a
   state directory that survives restarts:

   ```yaml
   controlPlane:
     endpoint: https://control-plane:7070/policy
     caCert: /etc/warden/certs/proxy-ca.crt
     stateDir: /var/lib/warden-worker      # absolute, 0700, a persistent volume
     enrollment:
       tokenEnv: WARDEN_WORKER_ENROLL_TOKEN
   central:
     mode: worker
     endpoint: https://control-plane:7070/central/ingest
     proxyID: worker-3                     # optional; must equal the id in the certificate
   ```

3. Start the worker. It posts its CSR to `/control/enroll`, persists the certificate
   and starts renewing. Check `GET /dashboard/api/workers`: the worker shows
   `authKind: cert` with `certSerial` and `certNotAfter`. The control plane logs
   `worker.enrolled` in the admin audit log (actor `enroll:<token id>`).

A restart reuses the persisted certificate and does not enroll again; the token is
only read when no valid certificate is on disk. A worker started before the control
plane (or while the CA is degraded) denies all egress and retries in the
background.

For a replica pool use one prefix-bound token, `--worker-id-prefix pool-a-
--max-uses 3`; each replica sends its suffix (the host name, or the value of the
variable named by `controlPlane.enrollment.workerIdSuffixEnv`) and becomes
`pool-a-<suffix>`. Leave `central.proxyID` unset in a pool.

## Renewal failure and expiry

Symptoms, most specific first:

- The worker gauge `warden_worker_cert_expiry_seconds` keeps falling instead of
  jumping back to the full lifetime at about 50% of it (12h with the default TTL).
- `warden_worker_cert_renewals_total{outcome}` stops counting `ok` and counts
  `error`, `rate_limited`, `unauthorized` or `rejected`.
- Worker log: `worker cert renewal failed; keeping the current certificate` WARNs with a
  growing retry delay (5s up to 5m), and once the certificate has expired an hourly ERROR `worker cert expired`.
- Control plane: `GET /dashboard/api/workers` shows a `certNotAfter` that is not
  moving, and `warden_cp_worker_renew_total{outcome}` and `warden_cp_worker_auth_total{kind=cert,outcome}` show the
  refusals (these CP counters are in memory until the CP metrics endpoint ships).

Causes and what to do:

| Outcome or log | Cause | Do |
|---|---|---|
| `error`, control plane unreachable | CP down, network, TLS passthrough broken | Fix the path. A 24h certificate tolerates about 12h without a control plane. |
| `error`, 503 `ca_unavailable` | The CA key cannot be loaded (`/healthz` says `degraded: worker_ca key unavailable`) | Restore the key backend; the CP retries every 30s. Verification of existing certificates is unaffected. |
| `rate_limited`, 429 | At most one renewal per worker per 10 minutes | Wait; the worker retries by itself. |
| `unauthorized`, 401 | The certificate was revoked, expired, or its lineage was cut | Re-enroll (below). |
| `error`, 400 | A bad CSR, or the new key equals a recent one | Re-enroll if it persists. |
| `rejected` | The control plane's answer failed the worker's checks (wrong worker id or trust domain) | Check the worker is talking to the right control plane; re-enroll. |

**An expired certificate gets no grace.** The worker keeps enforcing its
last-known-good default-deny policy and logs the ERROR above; it does not fall back
to a token.

### Re-enroll a worker

Needed after expiry, after a revoke, or after `worker.cert_lineage_conflict`.

1. Mint a new token with a new name (a name is never reused; a revoked or used-up
   token cannot be revived):

   ```sh
   warden control-plane enroll-token create --name worker-3-2 --worker-id worker-3 \
     --config F --state-dir D --out ./worker-3.enroll
   ```

2. On the worker, remove the old pair so it enrolls again (an expired certificate
   enrolls by itself, a revoked one does not know it was revoked):
   `rm <stateDir>/cert/worker-cert.pem <stateDir>/cert/worker-key.pem`.
3. Put the new token in the worker's environment variable and restart the worker.
4. Confirm `authKind: cert` and a new `certSerial` in the fleet view.

## Revoke a worker

Cuts the worker off the control plane at once and blocks its renewals; it keeps
enforcing its last-known-good policy (default-deny) until it re-enrolls.

- Console: the Revoke button in the fleet view (`console.auth: oidc`, admin).
- API: `POST /dashboard/api/workers/{id}/revoke` (admin; an optional body
  `{"serial": "<hex>"}` revokes one certificate).
- CLI, with the control plane running or stopped (a running one sees it within
  about 2 seconds):

  ```sh
  warden control-plane worker revoke --id worker-3 --state-dir D
  warden control-plane worker revoke --id worker-3 --serial 3f9a... --state-dir D
  ```

Every certificate of the worker is revoked together with its unused id-bound
enrollment tokens, its next `/policy`, `/control/heartbeat`, `/central/ingest` or
`/control/renew` is a 401 and its held long-poll ends within a second. Each revoke
appends a `worker.revoked` admin audit row. To bring the worker back, re-enroll it
with a new token.

To retire a leaked enrollment token that was never used: `warden control-plane
enroll-token revoke --id et_... --state-dir D` (`enroll-token list` shows the ids).

## Lineage-conflict alerts

A worker's certificates form a chain: each renewal names the certificate it
replaces. A renewal from a certificate that is not the latest (and not the
immediate predecessor of a successor the control plane has not seen used) means two
holders of one key lineage: a cloned key, or a worker restored from an old
snapshot.

The control plane revokes the worker (all its certificates and unused enrollment
tokens), cuts its held long-polls and appends the admin audit row
`worker.cert_lineage_conflict`. Alert on that action. Then:

1. Find the copy: which hosts hold `<stateDir>/cert/worker-key.pem` for this id, and
   was a worker volume restored or cloned?
2. Remove the key from every host that should not have it.
3. Re-enroll the legitimate worker with a new token (above).

A control plane restart clears the "successor seen" memory, which widens the
10-minute grace; an ordinary lost renewal response is retried up to 3 times from
the predecessor and is not a conflict.

## Rotate the intermediate

The control plane verifies against the pinned chain `workerCA.certFile` plus an
optional `workerCA.previousCertFile`. Live certificates are valid for `certTTL` (24h
by default), so the old chain must stay pinned for at least that long after the
last certificate it signed.

1. Keep the current chain: `cp worker-ca/intermediate-chain.pem worker-ca/previous-chain.pem`.
2. Create the new intermediate. With an offline root: stop the control plane, run
   `warden control-plane ca csr --state-dir D --config F`, have the root sign the
   printed CSR and install the chain at `workerCA.certFile`. For a development CA:

   ```sh
   warden control-plane ca init --out-dir ./worker-ca --trust-domain warden.local \
     --key-source file --state-dir D --config F --force
   ```

   In the compose recipe the files live in the `cp-ca` volume: run it through
   `docker compose exec` (or a one-off `run --rm` with `cp-ca` mounted read-write) with
   `--out-dir /ca`, after copying the old chain aside inside that volume.

   (`--force` replaces the stored `ca` key, so stop the control plane first, and
   writes a new root: move `root.key` offline again.)
3. In the control plane's config set `workerCA.previousCertFile` to the saved chain
   and `workerCA.certFile` to the new one, then start the control plane. Renewals
   now issue from the new intermediate; certificates it signed earlier still verify.
4. After at least `certTTL` (allow two, so every worker has renewed at least once
   while healthy), remove `workerCA.previousCertFile` and restart the control plane.
   A worker that was offline longer than that has an expired certificate and
   re-enrolls.

The control plane restarts in steps 3 and 4 are not an egress outage: workers keep
enforcing their last policy, and certificates keep verifying from the pinned chain
while the CA key is loading. A WARN with `not_after` appears when the intermediate
has under 30 days left; an expired `previousCertFile` is ignored with a WARN.

## CA key custody

- **Production:** `workerCA.keySource: keys`. The intermediate key lives in the key
  manager's key store (purpose `ca`, never rotated on a schedule), separate from
  the worker-facing secret store. Keep `root.key` offline, never on the control
  plane host, and sign new intermediates with it only when rotating.
- **Development only:** `keySource: file` keeps the intermediate key in a plain
  file (mode 0600, outside `--state-dir`); the control plane logs a development-only
  WARN at every start. The compose recipe does this, in its own `cp-ca` volume, and
  deletes `root.key` right after `ca init`.
- Nothing in `/policy`, logs or the audit log carries a key, a CSR or a token; the
  fleet API and the console never show an enrollment token or its hash.
- **Worker roles get no access to the control plane's secrets.** With `keySource:
  keys` on AWS the intermediate key is a secret at `<keys.store.aws.namePrefix>ca/<kid>`,
  by default `warden-cp-keys/ca/...`: it is **not** under `warden/cp/`. Give every
  worker role an explicit IAM deny on `warden-cp-keys/*` (your `keys.store.aws.namePrefix`
  if you changed it), as in the worker-role policy under [Signing
  keys](../control-plane.md#signing-keys-keys). As defense in depth also deny
  `warden/cp/*` and `warden/cp-??????`, the reserved namespace of the shared secret store
  ([Reserved `cp/` secret namespace](../control-plane.md#reserved-cp-secret-namespace)).
- Back up the CA volume or key store with the control plane's state: a lost
  intermediate key means every worker re-enrolls under a new intermediate.

## Strict mode and rollback

`--require-worker-certs` accepts certificates only: a `wwt_` token, the shared token
and an anonymous caller get 401. Turn it on only when every worker shows `authKind:
cert`. To roll back, restart the control plane without it (it then accepts a
certificate next to the tokens it still holds, in `strict` or `mixed` mode).
