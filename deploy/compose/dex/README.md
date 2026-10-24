# Reference Dex configuration

Reference config for the identity provider that Warden's identity features test
against. Warden treats Dex as a generic OIDC issuer: nothing under `internal/`
or `cmd/` names it, and every Dex-specific string lives in this directory.
This directory holds configuration only. The pinned compose recipe and seeded
LDAP arrive with W-P1-DEX-02.

## Files

| File | Purpose |
|---|---|
| `config.yaml` | Prod-shaped example. https issuer **placeholder**, no password grant, LDAP over StartTLS. Not used by any test stack. |
| `config.dev.yaml` | **Dev only.** Differs from `config.yaml` in exactly: the issuer, the `warden-cli` device callback, `oauth2.grantTypes` (adds `password`), `oauth2.passwordConnector`, and the LDAP transport (`insecureNoSSL`). `test/deploy` asserts this. |

Both files also set `web.http: 0.0.0.0:5556`, `telemetry.http: 0.0.0.0:5558`,
sqlite3 storage at `/var/dex/dex.db`, and `logger: {level: info, format: json}`
(debug logging is forbidden: it can log request material).

## Clients

| Client | Kind | Why it exists |
|---|---|---|
| `warden-console` | confidential (`secretEnv: WARDEN_CONSOLE_DEX_CLIENT_SECRET`), redirect `https://localhost:7070/auth/callback` | Admin SSO login to the control-plane console (browser code flow). |
| `warden` | confidential (`secretEnv: WARDEN_DEX_CLIENT_SECRET`), no redirect URIs, `trustedPeers: [agent-harness, warden-cli]` | The data-plane audience. It never logs anyone in. Tokens minted for the harness and the CLI carry `warden` in `aud` through cross-client scopes. |
| `agent-harness` | confidential (`secretEnv: HARNESS_DEX_CLIENT_SECRET`) | Test and automation client that fetches ID tokens for seeded users. |
| `warden-cli` | `public: true`, redirect includes `<issuer>/device/callback` | Human CLI login with the device-code grant. |

**Why console and data-plane are split.** The console client has a browser
redirect and a secret held by the control plane; the data-plane client is only
an audience that workers check on every proxied request. A leaked console
secret must not let anyone mint tokens the data plane accepts, and the data
plane must not have a redirect URI an attacker could steer a login to.

**trustedPeers direction.** `warden` lists `agent-harness` and `warden-cli` as
trusted peers, which lets those two clients request the scope
`audience:server:client_id:warden` so their ID tokens carry `warden` in `aud`.

**Why `warden-cli` is public.** A CLI on a developer's machine cannot keep a
secret, so it has none (no `secretEnv`, no `secret:`). The device-code grant
needs no secret and no local listener. Dex derives the device callback from the
issuer (`<issuer>/device/callback`), which is why that URI differs per file.

## Required scopes

`openid email profile groups offline_access`. The harness and CLI add
`audience:server:client_id:warden`.

## Grants

`authorization_code`, `refresh_token` and
`urn:ietf:params:oauth:grant-type:device_code`, with `responseTypes: [code]`.

The `password` grant exists only in `config.dev.yaml` (with
`passwordConnector: ldap`). It makes the client handle the user's password and
skips the IdP's own login page, so it is a test convenience for scripts, never
for production.

Expiry: ID tokens 1h, signing keys 6h, device requests 5m, refresh tokens valid
if used within 168h with a 720h absolute lifetime, 3s reuse interval, rotation
on.

## Split horizon

The dev issuer is `http://localhost:5556/dex`. Dex is published on
`127.0.0.1:5556`, so browsers and host CLIs reach it with no hosts entry. The CP
and workers run in containers where `localhost` is themselves, so they set
`internalIssuerURL: http://dex:5556`: Warden sends server-side discovery, JWKS
and token-exchange calls for the issuer's origin to that internal origin, while
the issuer string, path, headers and tokens stay public. Production uses one
https issuer reachable by everything and leaves `internalIssuerURL` unset.

## Permanence

- **The connector id is permanent.** `id: ldap` is encoded into every user's
  `sub`. Renaming it makes every user a new person.
- **The issuer string is permanent too.** Identity is keyed by `(issuer, sub)`,
  so changing the issuer later makes every user a new person: block list
  entries, attribution and per-user secrets keyed by `secrets.UserKey(iss, sub)`
  stop matching. Set the final public https issuer before real users exist.

## Approval screen

`oauth2.skipApprovalScreen: true` stays: the approval screen returns HTTP 500
("Approval rejected") with a static client plus a local connector on v2.41.1,
and a throwaway IdP does not need it.

## Secrets and env expansion

Decision: **the LDAP connector uses `bindPW: $LDAP_BIND_PW`, and there is no
top-level `expandEnv` key.**

Checked against the v2.41.1 source: env expansion is not a config key there. It
is the feature flag `expand_env` (`pkg/featureflags/set.go`:
`ExpandEnv = newFlag("expand_env", true)`), on by default, and `cmd/dex/config.go`
applies `os.ExpandEnv` to the raw `config:` block of storage and of every
connector (the `featureflags.ExpandEnv.Enabled()` branches). Setting
`DEX_EXPAND_ENV=false` turns it off, so never set that. Because the whole raw
block is expanded, a literal `$` in any connector value must be written as an
env reference too.

Static clients use `secretEnv` (read by `cmd/dex/serve.go`), never `secret:`.
`scripts/check-secrets.sh` (gate stage `secrets`) fails when `secret:`,
`bindPW:` or `clientSecret:` under this directory or
`deploy/compose/docker-compose.identity.yml` is not `$VAR` or `${VAR...}`; only
`seed.ldif` is allowlisted. `test/deploy` asserts the `bindPW` form.

## Pinned release

Tested baseline: `ghcr.io/dexidp/dex:v2.41.1`. W-P1-DEX-02 adds the image
digest. A later bump is its own change that re-runs the runtime proofs
(W-P1-DEX-06).

## Replacing Dex

Warden speaks only standard OIDC. To use another issuer:

1. Do not merge `docker-compose.identity.yml`; run your IdP instead.
2. Register the same four roles there: a confidential console client with
   redirect `<cp-url>/auth/callback`; a data-plane audience; a harness client
   and a public device-code CLI client whose ID tokens carry that audience (or
   list each client id in `identity.audiences`).
3. Set the config keys: worker `identity.issuer/audience/audiences/allowedAZP/groupsClaim`,
   CP `console.oidc.*` and `console.roles`, CLI `--issuer --client-id --scopes`.
4. Add the new recipe directory to `SECRET_SCAN_PATHS` in
   `scripts/check-secrets.sh`.

No Go change is needed.

## Tests

```sh
go test ./test/deploy -run 'TestDexReferenceConfig|TestCheckSecretsScript'
```

These are static: no container starts. Runtime checks arrive with the compose
recipe (W-P1-DEX-02) and W-P1-DEX-06.
