# Runbook: break-glass console login

Break-glass is a local emergency admin login for the console. Use it when the
identity provider (Dex) is down and an admin must still change policy, block a
user or revoke a worker token. It is **off by default**, it needs TLS, and every
attempt is logged, audited and alerted. Reference for the mechanics:
[Console sign-in config](../control-plane.md#console-sign-in-config).

The drill below is the one the tests run: `go test ./cmd/proxy -run
TestControlPlaneBreakGlassDegraded` (in-process, issuer unreachable) and
`make e2e-identity-scenario NAME=TestBreakGlassDexDown` (the real Dex container
stopped and the control plane restarted). Run the second one under the shared
e2e lock if other agents use the machine.

## What it is, and what it is not

- `POST /auth/breakglass` with `{"username","password"}` opens an `admin` session
  with `auth_method` `breakglass`. It is mounted only when
  `console.breakGlass.enabled` is true; otherwise it answers `404`.
- The control plane keeps serving `/policy`, `/control/heartbeat` and
  `/central/ingest` while the IdP is unreachable, so workers are unaffected.
  `/auth/login` answers `503 idp_unavailable` until IdP discovery succeeds.
- The password is checked against an argon2id hash held in an env var or a file.
  The hash is never in `config.yaml`.
- It needs `console.auth: oidc` and `--state-dir`. It is not a general second
  login: keep the hash disabled or rotated except during an incident.

## 1. Prepare it (before the incident)

Generate a hash. The password is read from a terminal with echo off (asked
twice), or as one line on stdin with `--stdin`. There is no password flag, so the
password never appears in argv, and only the hash reaches stdout. The minimum
length is 16 characters.

```sh
read -rs BREAKGLASS_PW && printf '%s\n' "$BREAKGLASS_PW" | warden control-plane hash-password --stdin > /secure/warden-breakglass.hash
unset BREAKGLASS_PW
```

The output is one PHC line of this shape (placeholder, not a real hash):

```
$argon2id$v=19$m=65536,t=3,p=2$PLACEHOLDERSALT$PLACEHOLDERHASH
```

Store the password in your password manager or a sealed envelope, not on the
control plane host. Put the **hash** where the control plane can read it, and name
it in the config. Set exactly one of `passwordHashEnv` and `passwordHashFile`:

```yaml
console:
  auth: oidc
  # oidc: ... as for normal sign-in
  breakGlass:
    enabled: true
    username: breakglass-admin          # the name you will log in as
    passwordHashFile: /run/secrets/warden-breakglass-hash   # or passwordHashEnv: WARDEN_BREAKGLASS_HASH
    sessionTTL: 1h                      # default 1h, maximum 4h
    allowBehindTLSTerminator: false     # see "TLS" below
  adminAudit:
    enabled: true                       # without it, logins leave no signed audit row
integrations:
  - type: webhook
    name: sec-alerts
    config:
      url: "${WARDEN_WEBHOOK_URL}"
    match:
      - rule: breakglass_login          # routes both the critical success and the high failures
      - rule: backup_failed
      - rule: backup_stale
```

The config holds only the **name** of the env var or file. A `passwordHashFile`
is re-read on every attempt, so a mounted secret can be rotated without a restart;
a `passwordHashEnv` value is fixed for the process, so changing it needs a restart.

### TLS

Break-glass sends a password, so the control plane refuses to start with it
enabled while serving plain HTTP on a non-loopback `--listen` address. Give it
`--ca-cert` and `--ca-key` (it then mints its own server certificate). If TLS ends
at a proxy in front of the control plane, set
`console.breakGlass.allowBehindTLSTerminator: true` to say so; the session cookie
is still marked `Secure`.

### Startup checks

The control plane refuses to start when `--state-dir` is empty, when the hash is
missing, unreadable or outside the argon2id bounds (the error names
`console.breakGlass.passwordHashEnv` or `passwordHashFile`, never the value), and
for the TLS rule above. It logs a WARN at startup when no alert pipeline exists,
when no integration's `alerts.match` routes a critical `breakglass_login` Finding,
and when `console.adminAudit.enabled` is false. Fix every WARN before relying on
break-glass: each means a login would happen silently or unrecorded.

## 2. During the incident: log in

Take the password from your secret store into a shell variable (it must not be
typed on a command line that lands in shell history), then post it as JSON on
stdin. `--resolve` pins the certificate's host name to an address, which is
useful when DNS is part of the outage:

```sh
read -rs BREAKGLASS_PW
jq -n --arg u breakglass-admin --arg p "$BREAKGLASS_PW" '{username:$u,password:$p}' \
  | curl -sS --cacert ca.pem --resolve cp.example.internal:7070:10.0.0.5 \
      -c bg-cookies.txt -H 'Content-Type: application/json' -d @- \
      https://cp.example.internal:7070/auth/breakglass
unset BREAKGLASS_PW
```

| Status | Body | Meaning |
|---|---|---|
| `200` | `{"ok":true,"expiresAt":"..."}` and a `Secure` session cookie | Logged in. The session is `admin`, expires at `expiresAt` and activity never extends it. |
| `401` | `{"error":"invalid_credentials"}` | Wrong username or wrong password (indistinguishable by body and by timing). |
| `404` | | Break-glass is not enabled on this control plane. |
| `429` | `{"error":"rate_limited"}` with `Retry-After`, or `{"error":"busy"}` | Too many failures, or two verifications already running. Wait, do not retry in a loop. |
| `503` | `{"error":"breakglass_unavailable"}`, `audit_unavailable` or `session_unavailable` | The hash cannot be read right now; or admin audit is on and the row could not be written (the login fails closed and no session is created); or the session could not be stored. |

Other refusals are `400 bad_request`, `403 origin` (an `Origin` header that is not
the control plane's own), `405`, `413 body_too_large` (over 4 KiB) and `415
content_type` (not `application/json`).

Rate limits: 5 failed attempts per client address (the TCP peer address, never
`X-Forwarded-For`) and 20 in total, each per 15 minutes. **The limiter is in
memory and resets when the control plane restarts**, so a restart clears a lockout
(and an attacker's count).

The dashboard has no break-glass form. For the browser, copy the session cookie
from `bg-cookies.txt` (`__Host-warden_console` over TLS) into the browser's
cookie store for the control plane's host, then reload `/dashboard/`. For scripted
calls, keep using `curl -b bg-cookies.txt`. A write needs the session's CSRF token,
which `GET /auth/me` returns:

```sh
curl -sS --cacert ca.pem -b bg-cookies.txt https://cp.example.internal:7070/auth/me
# {"role":"admin","authMethod":"breakglass","csrf":"...","expiresAt":"..."}
```

Writes need the `X-Warden-CSRF` header with that `csrf` value, exactly as for any
console session.

### What the session looks like

- The dashboard shows a **red banner** with the expiry time for the whole session.
- Lifetime is `console.breakGlass.sessionTTL` (default `1h`, maximum `4h`), absolute:
  there is no idle timeout and no extension.
- A new break-glass login revokes the earlier break-glass session.
- While any break-glass session is live the control plane logs the WARN
  `breakglass_session_active` (count and earliest expiry, no session id) every
  5 minutes.

## 3. After the incident

1. **End the session.** Sign out (`POST /auth/logout`, with the CSRF header) or wait
   for the expiry. The logout is audited with `auth_method` `breakglass`.
2. **Disable or rotate the hash.** Either set `console.breakGlass.enabled: false` and
   restart the control plane, or generate a new hash (step 1) and replace the file
   (no restart) or the env var (restart). Treat the old password as burned.
3. **Review what was done.** With admin audit on, every action of the session is a
   signed row with `auth_method` `breakglass` and actor `breakglass:<username>`.
   In the shipped `warden.admin.v1` JSON log ([SIEM guide](../siem.md)):

   ```sh
   jq -c 'select(.schema=="warden.admin.v1" and .auth_method=="breakglass")' admin-audit.jsonl
   ```

   Offline, `warden control-plane admin-audit verify --state-dir /data` checks the
   chain, and `warden control-plane admin-audit export --state-dir /data --out
   /backup/admin-audit.jsonl` writes it for review. A login also logs one ERROR line
   `msg=breakglass_login` (outcome, client address, and on success the first 8
   characters of a session hash), never a password or the submitted username.
4. **Confirm the alert fired.** Every attempt publishes a `breakglass_login`
   Finding: critical for a login, high for a failure (failures aggregate by count).
   Check that the on-call channel received the critical one. If it did not, the
   `alerts.match` route in step 1 is wrong; fix it before the next incident. The
   control plane has no metrics endpoint in P1, so the alert and the ERROR log
   line are the signals.
5. **Look for failures you did not make.** A burst of `outcome=invalid_credentials`
   or `rate_limited` lines with an unknown `client_ip` means someone is guessing.
   Rate-limited requests are aggregated into at most one audit row per address per
   window.

## Known limits

- Rate limits are per process and in memory. They reset on restart and are not
  shared between control plane instances (P1 runs one per state dir).
- One break-glass account. There is no per-person login and the audit row names the
  configured username, not a human. Record who held the password in your incident
  log.
- Break-glass does not bypass the roles matrix: it is an `admin` session, which can
  do everything an admin can. Keep it off outside incidents.
