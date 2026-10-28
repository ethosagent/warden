# Running Dex as Warden's identity provider

This is the operator guide for the reference identity provider (IdP). Warden
needs only a **standards OIDC issuer**: nothing in `internal/` or `cmd/` calls a
Dex-specific API, and any issuer that publishes discovery and a JWKS and signs
RS256 or ES256 ID tokens can replace Dex (see
[`deploy/compose/dex/README.md`](../deploy/compose/dex/README.md), "Replacing
Dex"). Dex is what the recipe, the compose stack and the L2 proofs use, so this
page documents it.

**Tested baseline.** `ghcr.io/dexidp/dex:v2.41.1`, pinned by tag and by the
multi-arch index digest
`sha256:bc7cfce7c17f52864e2bb2a4dc1d2f86a41e3019f6d42e81d92a301fad0c8a1d`
(`deploy/compose/docker-compose.identity.yml`). The recipe and the L2 proofs
(`make e2e-identity-scenario NAME=TestDex`) were tested on that version. A later
bump is its own change (new tag and digest) that re-runs those proofs.

Related pages: the [agent identity contract](identity-contract.md) (what a
harness sends and what the worker does with it), the
[control plane](control-plane.md#console-sign-in-config) (`console:` block,
sessions, roles), the [Docker end-to-end guide](docker-end-to-end.md#the-l2-identity-stack-make-e2e-identity)
(the stack the commands below run on) and the [setup guide](setup-guide.md).

Three tests keep this page honest. `go test ./test/deploy -run
'TestIdentityDexDoc'` parses every `warden-cp` and `warden-worker` YAML block
here with the strict config loaders (a renamed key fails it) and checks the
page's limits, links and forbidden words. `make e2e-identity-scenario
NAME=TestDexDocRunBlocks` executes every `sh run` block here, in order, against
the L2 identity stack and compares the output shown under it.

## 1. Token flow

```text
harness or CLI --(device code on warden-cli | authorization code on agent-harness)--> Dex
Dex --> ID token: aud contains "warden", azp = the requesting client
harness --> worker:  Proxy-Authorization: Basic base64("session:<token>")   (CONNECT)
                 or  X-Warden-Identity: Bearer <token>                       (terminated TLS)
worker --> internal/identity verifies the token and records who made the request
```

- A human on a laptop logs in with the public `warden-cli` client through the
  RFC 8628 device-code grant (`warden identity login`). A harness platform logs
  its user in with the confidential `agent-harness` client (authorization code)
  and refreshes server-side.
- The ID token carries `warden` in `aud` through Dex's cross-client scope
  `audience:server:client_id:warden`, and the requesting client in `azp`.
- The worker accepts the token in `Proxy-Authorization` on CONNECT (Basic, user
  name `session`, or Bearer) or in `X-Warden-Identity`. The exact header rules,
  statuses and limits are in the [identity contract](identity-contract.md); this
  page does not repeat them.
- **Tokens are obtained outside the agent sandbox.** The agent has no route to
  Dex (Dex is never on an agent network), so it cannot log in or refresh by
  itself. The only way to refresh from inside a sandbox is through the worker,
  and only when an operator adds an explicit allow rule for the issuer's token
  endpoint; default-deny otherwise.
- Phase 1 is attribution only: a bad, expired or missing token is recorded and
  the request still goes through. Default-deny egress policy is unchanged.

## 2. Clients and scopes

The recipe registers four static clients (`deploy/compose/dex/config.yaml`):

| Client | Kind | Secret env name | Redirect URI | Purpose |
|---|---|---|---|---|
| `warden-console` | confidential | `WARDEN_CONSOLE_DEX_CLIENT_SECRET` | `https://localhost:7070/auth/callback` (dev), `https://<cp-host>/auth/callback` (prod) | Admin SSO login to the control-plane console (browser code flow). |
| `warden` | confidential | `WARDEN_DEX_CLIENT_SECRET` | none | The data-plane audience. It never logs anyone in; it only appears in `aud`. |
| `agent-harness` | confidential | `HARNESS_DEX_CLIENT_SECRET` | none | A harness platform's login client (and the dev token script). |
| `warden-cli` | public | none | `<issuer>/device/callback` and `/device/callback` | Human CLI login with the device-code grant. A CLI cannot keep a secret. |

Redirect URIs are written **as the browser sees them**, not as a container sees
them: the console redirect is the public URL of the control plane, and the CLI
device callback is derived from the public issuer.

**Why console and data-plane clients are separate.** The console client has a
browser redirect and a secret the control plane holds. The data-plane client is
only an audience that workers check on every proxied request. A leaked console
secret must not let anyone mint tokens the data plane accepts, and the data
plane must not have a redirect URI an attacker could steer a login to. A console
login token never carries `aud` `warden`, and console login accepts only `aud`
`warden-console`, so a harness token is never a console token and the reverse.

**`trustedPeers` direction.** The `warden` client lists `agent-harness` and
`warden-cli` as `trustedPeers`. That is what lets those two clients request the
scope `audience:server:client_id:warden` and get `warden` in `aud`.
`warden-console` is not a trusted peer, so it cannot.

**Required scopes.** Harness and CLI request

```text
openid email profile groups offline_access audience:server:client_id:warden
```

`groups` is required (without it the token has no groups claim, so no group
policy and no console role) and so is `offline_access` (without it there is no
refresh token and the login ends when the 1 h ID token expires). The console
requests `openid email profile groups` and deliberately not `offline_access`: it
stores no IdP token of any kind.

## 3. Groups, roles and keys

Warden does not define groups; it reads the `groups` claim Dex issues. The
recipe's seeded directory (`deploy/compose/dex/seed.ldif`, dev only) has
`warden-admins`, `warden-editors`, `warden-viewers` and `eng`: alice is in
`warden-admins` and `eng`, bob in `warden-editors`, carol in `warden-viewers`,
and dave in `eng` only. These names are recipe defaults, not a contract.

**Console roles come only from IdP groups.** The control plane reads the
`console:` block of its operator-owned `--config` file (never the `--state-dir`
copy). Matching against `console.roles.admin`, `console.roles.editor` and
`console.roles.viewer` is exact and case-sensitive, and the highest matching
role wins. A user whose groups match none gets no console access (login fails
with `no_role`). `console.roles.admin` needs at least one group. There is no
other source of roles: not email, not a user list.

Dev (split-horizon issuer, see section 5):

```yaml warden-cp
console:
  auth: oidc
  oidc:
    issuer: http://localhost:5556/dex
    internalIssuerURL: http://dex:5556
    clientID: warden-console
    clientSecretEnv: WARDEN_CONSOLE_DEX_CLIENT_SECRET
    redirectURL: https://localhost:7070/auth/callback
  roles:
    admin: [warden-admins]
    editor: [warden-editors]
    viewer: [warden-viewers]
```

Production: one https issuer that browsers, CLIs, the control plane and workers
all reach, and no `internalIssuerURL`:

```yaml warden-cp
console:
  auth: oidc
  oidc:
    issuer: https://dex.example.com/dex
    clientID: warden-console
    clientSecretEnv: WARDEN_CONSOLE_DEX_CLIENT_SECRET
    redirectURL: https://warden.example.com/auth/callback
  roles:
    admin: [warden-admins]
    editor: [warden-editors]
    viewer: [warden-viewers]
  session:
    idle: 1h
    absolute: 12h
```

The control plane holds the secret's env var **name**; the value comes from a
secret manager or a Kubernetes Secret and is never in the file. In `oidc` mode
the control plane also needs `--state-dir` (sessions and pending logins live in
`<state-dir>/warden-cp.db`).

**Worker identity.** The worker's `identity:` block, in its local YAML or served
by the control plane, names the issuer it trusts:

```yaml warden-worker
policy:
  allowlist:
    - domain: api.example.com

identity:
  defaultMode: attribute
  issuer: http://localhost:5556/dex
  internalIssuerURL: http://dex:5556
  audience: warden
  allowedAZP: [agent-harness, warden-cli]
```

```yaml warden-worker
policy:
  allowlist:
    - domain: api.example.com

identity:
  defaultMode: attribute
  issuer: https://dex.example.com/dex
  audience: warden
  allowedAZP: [agent-harness, warden-cli]

# A per-agent mode overrides identity.defaultMode for that agent id.
agents:
  - id: research-bot
    identity: attribute
```

- `defaultMode` is `off` (the default) or `attribute`; `require` is a later
  phase and is rejected. `agents[].identity` overrides it for one agent.
- `issuer` and `audience` are required once any mode is `attribute`.
  `allowedAZP` has no built-in default: empty means no `azp` check, so set it to
  `[agent-harness, warden-cli]` and a token minted for any other client (the
  console client included) is rejected.
- Optional: `jwksURL`, `groupsClaim`, `clockSkewSeconds` (0 to 300, default
  60) and `maxTokenTTLSeconds` (default 3600).

**`sub` is the identity.** Dex's `sub` is opaque: it encodes the connector id
together with the upstream user id. Identity is keyed by `(iss, sub)`; email is
a display attribute only. To see the parts while debugging, add the scope
`federated:id` to a login: the ID token then carries a `federated_claims` object
with `connector_id` and `user_id`. It is for diagnostics, never for keys.

**The connector `id` is permanent.** It is part of every `sub`. Renaming a
connector (the recipe's is `ldap`), or moving people from one connector to
another, makes every user a new person: block list entries, attribution and
per-user secrets keyed by `(iss, sub)` (`secrets.UserKey(iss, sub)` for stored
credentials) stop matching, and re-keying that state is manual work. Pick the id
once, before real users exist. The issuer string is permanent for the same
reason (section 5).

A decoded token from the dev stack looks like this (claims only; no token is ever
shown on this page):

```json
{
  "iss": "http://localhost:5556/dex",
  "sub": "<opaque, encodes connector id and user id>",
  "aud": ["agent-harness", "warden"],
  "azp": "agent-harness",
  "email": "alice@example.org",
  "groups": ["eng", "warden-admins"],
  "iat": 1700000000,
  "exp": 1700003600
}
```

## 4. Connectors

Warden sees only the token, so a connector's job is to put the right user id and
group names in it. Group names differ by connector, and `console.roles` and any
group policy must use the strings the connector actually emits.

| Connector | Groups come from | Group claim shape | Scope that triggers them | Refresh re-checks the upstream user |
|---|---|---|---|---|
| LDAP | `groupSearch` against the directory | the `nameAttr` value, for example `warden-admins` (cn) | `groups` | Yes: Dex looks the user and the groups up again on every refresh |
| GitHub | team membership in the listed `orgs` | `org:team` (display name by default; `teamNameField: slug` or `both` change the team part) | `groups` (the `orgs` or `org` setting selects which teams) | Yes: Dex re-reads the user and teams with the stored upstream access token |
| Google | Workspace groups through the Admin Directory API | the group email address | `groups` | Yes, with the upstream refresh token; Dex re-fetches the groups |
| Upstream OIDC | the upstream's own `groups` claim (`claimMapping.groupsKey`) | whatever the upstream issues | `groups`, and `insecureEnableGroups: true` on the Dex connector | Only if the upstream grants a refresh token (add `offline_access` to the connector `scopes`) |

"Refresh re-checks" matters for offboarding: a removed group takes effect at the
next ID-token refresh (at most 1 h), but a person who is deleted upstream and
whose connector cannot re-check keeps refreshing until the refresh token's
absolute expiry. Prefer connectors and settings that re-check, and use the
block list (section 6) to cut a person off at once.

All connector secrets come from the environment: Dex expands `$VAR` in
connector `config:` blocks (feature flag `expand_env`, on by default; never set
`DEX_EXPAND_ENV=false`), so write `clientSecret: $GOOGLE_CLIENT_SECRET`, never a
literal. `scripts/check-secrets.sh` fails the gate on a literal under
`deploy/compose/dex/`.

### LDAP

The recipe's connector (`deploy/compose/dex/config.yaml`). In production use
`ldaps://` in `host` or StartTLS verified against `rootCA`; `insecureNoSSL` is
for the dev directory only. Scope `groupSearch` to the groups Warden needs
(section 7): a user in hundreds of groups produces a large token.

```yaml
connectors:
  - type: ldap
    name: LDAP
    id: ldap            # permanent: part of every sub
    config:
      host: ldap.example.com:389
      startTLS: true
      rootCA: /etc/dex/ldap-ca.pem
      bindDN: cn=admin,dc=example,dc=org
      bindPW: $LDAP_BIND_PW
      userSearch:
        baseDN: ou=people,dc=example,dc=org
        filter: "(objectClass=inetOrgPerson)"
        username: uid
        idAttr: uid
        emailAttr: mail
        nameAttr: cn
      groupSearch:
        baseDN: ou=groups,dc=example,dc=org
        filter: "(objectClass=groupOfNames)"
        userMatchers:
          - userAttr: DN
            groupAttr: member
        nameAttr: cn
```

### GitHub

```yaml
connectors:
  - type: github
    name: GitHub
    id: github          # permanent
    config:
      clientID: $GITHUB_CLIENT_ID
      clientSecret: $GITHUB_CLIENT_SECRET
      redirectURI: https://dex.example.com/dex/callback
      orgs:
        - name: example-org
          teams: [platform, security]
      teamNameField: slug
```

Groups are `org:team` strings such as `example-org:platform`. By default the
team part is the team's display name; `teamNameField: slug` uses the slug, and
`both` emits both. Only the listed teams appear (an org with no `teams` list
contributes the bare org name as a group).

### Google

Create an OAuth client in the Google Cloud console with the redirect URI
`https://dex.example.com/dex/callback`, and put its secret in the secret
manager that feeds `GOOGLE_CLIENT_SECRET`. Nothing below holds a secret value.

```yaml
connectors:
  - type: google
    name: Google
    id: google          # permanent
    config:
      clientID: $GOOGLE_CLIENT_ID
      clientSecret: $GOOGLE_CLIENT_SECRET
      redirectURI: https://dex.example.com/dex/callback
      hostedDomains: [example.com]
      # Groups need a service account with domain-wide delegation for the
      # read-only Directory group scope, mounted as a file from a secret
      # store, and a Workspace admin address it impersonates.
      serviceAccountFilePath: /etc/dex/google-sa.json
      domainToAdminEmail:
        example.com: admin@example.com
```

Without `serviceAccountFilePath` and `domainToAdminEmail` Google returns **no
groups**: the token has an empty groups list, the person can log in but gets no
console role (`no_role`), and group policy matches nothing. The same is true of
a personal Gmail account, which has no Workspace groups at all, so a personal
account can sign in and be attributed by `sub` and `email` but can never be an
admin, editor or viewer. Mount the service account JSON from a Kubernetes
Secret or a secret manager; never commit it, never put it in `deploy/`.

### Upstream OIDC

```yaml
connectors:
  - type: oidc
    name: Company SSO
    id: company-sso     # permanent
    config:
      issuer: https://sso.example.com
      clientID: $UPSTREAM_CLIENT_ID
      clientSecret: $UPSTREAM_CLIENT_SECRET
      redirectURI: https://dex.example.com/dex/callback
      scopes: [openid, profile, email, groups, offline_access]
      insecureEnableGroups: true
      claimMapping:
        groupsKey: groups
```

Adding a second connector adds a chooser page to the login. The same person
logging in through two connectors is two different `sub` values.

## 5. Issuer, transport and networks

**The issuer is one public string**, byte-identical in every token, in the
discovery document and in every redirect. Workers compare `iss` to
`identity.issuer` with no trailing-slash or case folding.

**Dev and demo: split horizon.** The issuer is `http://localhost:5556/dex`. Dex
is published on `127.0.0.1:5556`, so the browser and the CLI on the host reach
it directly: no hosts entry and no /etc/hosts edit is needed. A container cannot
reach `localhost:5556` (inside it, `localhost` is the container itself), so the
control plane and the workers set the optional `internalIssuerURL:
http://dex:5556` (`console.oidc.internalIssuerURL` and
`identity.internalIssuerURL`). Their server-side OIDC calls (discovery, JWKS,
token exchange) whose origin equals the issuer's origin go to the internal
origin, changing only the scheme, host and port of the TCP destination. The
issuer string, the path, the headers and the body never change, browser
redirects keep the public issuer, and every token keeps it. A plain-http issuer
is accepted only when an internal issuer URL is set (the dev profile); otherwise
https is required, and there is no flag to relax that. `internalIssuerURL` is an
origin only (no path, userinfo, query or fragment).

**Production: one https issuer** that browsers, CLIs, the control plane and the
workers all reach, with `internalIssuerURL` unset. Set `issuer:` in
`deploy/compose/dex/config.yaml` to the final public https URL.

**Every command meant to be run uses `http://localhost:5556` directly**, as
below (the issuer's `/.well-known/openid-configuration` returns the same issuer
string from the host as from a container):

```sh run
curl -fsS http://localhost:5556/dex/.well-known/openid-configuration | jq -r .issuer
```

```text
http://localhost:5556/dex
```

**Networks.** Dex sits on `cp-net` and `idp-net`, never on an agent network, so
a sandboxed agent has no path to it. The compose recipe publishes Dex only on
`127.0.0.1:5556`; its telemetry port 5558 is not published. LDAP is on the
internal `idp-net` only. An upstream connector (GitHub, Google, upstream OIDC)
makes Dex call out to the internet, so Dex then needs an egress network for
those calls, and for those calls only.

**The issuer string is permanent.** Identity is keyed by `(issuer, sub)`, so
changing the issuer later makes every user a new person: block list entries,
attribution and per-user secrets keyed by `secrets.UserKey(iss, sub)` stop
matching. Choose the final public issuer before real users exist. Moving Dex
behind a new hostname means keeping the old issuer string (Dex can serve it
behind the new name) or re-keying that state.

**Logout is local.** Console logout (`POST /auth/logout`) deletes the Warden
session and clears the cookie, nothing more. The Dex session stays, so the next
login can be silent, and no `id_token_hint` is sent because no IdP token is
stored. Logout is not how a person's access is removed: that is the block
list's job (section 6).

## 6. Rotation, failure modes and offboarding

**Key rotation.** Dex signs with a key it rotates every `expiry.signingKeys`
(`6h` in the recipe) and keeps the previous key in the JWKS until the tokens it
signed have expired, so rotation drops no valid token. Workers fetch keys
lazily: a token with an unknown `kid` triggers a JWKS refetch, at most once per
30 s, and the last good key set is kept when a fetch fails. Nothing to restart.

| Situation | What happens |
|---|---|
| Dex is down | New console logins fail (`/auth/login` and `/auth/callback` answer 503 `idp_unavailable` or the login fails with `exchange_failed`); existing console sessions keep working. Already-issued ID tokens verify until they expire (1 h), because workers keep their cached keys. `warden identity token` exits 3 once no valid cached token remains. Console access during an outage is the job of the planned break-glass login (feature p1-breakglass, not shipped yet). |
| LDAP (or the upstream) is down | New logins fail and refreshes fail. Tokens already issued keep verifying until `exp`. |
| JWKS unavailable when a worker starts | The worker starts and serves: it builds its verifier without contacting the issuer, and fetches keys on the first token. Until the fetch works, tokens are recorded as `unverified` (reason `jwks_unavailable`) and the request is still allowed in attribute mode. A failed fetch is retried at most every 30 s. |
| Clock skew over 60 s | Tokens are recorded `expired` (or rejected as not yet valid). Run NTP on Dex and on every worker. `identity.clockSkewSeconds` can widen the allowance to at most 300 s. |
| Storage lost (for example the sqlite file) | Dex generates new signing keys and forgets every refresh token and device code. Static clients and connectors come from the config file, and `sub` does not change (it comes from the connector id and the upstream id), so nobody becomes a new person; everyone logs in again. Old tokens fail `unknown_kid` after the refetch. Use persistent storage and backups (section 7). |
| Refresh token expired | A refresh token dies after 168 h without use (`validIfNotUsedFor`) or 720 h after login (`absoluteLifetime`); the user logs in again. |
| Refresh token reused | Rotation is on. The old token is accepted only for the 3 s `reuseInterval` (so two racing refreshes both work); later reuse fails with `invalid_grant` and the client logs in again. Never disable rotation. |

**Metrics.** The worker counts verifications in `warden_identity_verify_total`
with `result` and `reason` labels; alert on a rising share of
`result=~"invalid|unverified"` (a 15 minute rate above 0.2 of all
verifications is a sensible start; the contract has the exact query). Dex serves
Prometheus metrics and `/healthz` on its telemetry port (5558 in the recipe);
alert on Dex health and on its 5xx rate. The control plane logs one
`console_login` line per attempt with `result` and `reason`, never a code or
token.

**Offboarding.** Removing someone upstream does not end their access at once:
an ID token stays valid until `exp`, a console session lasts until its idle
(1 h) or absolute (12 h) limit unless an admin revokes it, and a refresh token
can outlive the upstream account on a connector that cannot re-check. The
control for removing access immediately is the user block list (roadmap
features W-P1-BLOCK-*: console login and sessions, and sessions already open
when a block lands). Logout is not a substitute for it.

## 7. Production checklist

- [ ] **https issuer**, final and public, byte-identical everywhere; `internalIssuerURL` unset on the control plane and workers.
- [ ] **Persistent, highly available storage.** The recipe's `sqlite3` is a single replica and for development. In production use Postgres or Kubernetes custom-resource storage and run at least 2 Dex replicas behind one issuer URL.
- [ ] **Backups** of the Dex storage, and a restore you have tried. Without it, a storage loss logs everyone out (section 6).
- [ ] **Password grant off.** `config.yaml` has no `password` grant and no `passwordConnector`; only `config.dev.yaml` (dev only) enables it. It makes a client handle the user's password and skips the IdP's login page.
- [ ] **Logger not `debug`.** Debug logging can log request material. Keep `level: info`, `format: json`.
- [ ] **Expiry values** the worker accepts: ID tokens `1h` (the worker refuses `exp - iat` over 1 h unless `identity.maxTokenTTLSeconds` is raised), signing keys `6h`, device requests `5m`, refresh tokens `validIfNotUsedFor: 168h`, `absoluteLifetime: 720h`, `reuseInterval: 3s`, rotation on.
- [ ] **Secrets from a secret manager or a Kubernetes Secret**: client secrets (`secretEnv`), the LDAP bind password, connector secrets, the Google service account file. No literals in the config or the repo.
- [ ] **LDAP over `ldaps://` or StartTLS with `rootCA`**, not `insecureNoSSL`.
- [ ] **`groupSearch` scoped** so tokens stay well under Warden's limits (below).
- [ ] **Static clients** match section 2, with the redirect URIs of your real hostnames; `warden-cli` stays public and `warden` has no redirect URI.
- [ ] **NTP** on Dex, the control plane and every worker.
- [ ] **Connector ids and the issuer reviewed** once more before the first real login.

**Limits to size tokens against.** A token is at most 16 KiB; larger is
rejected unread with reason `too_large`. The worker keeps at most 64 groups of
at most 256 bytes each from an agent token (the console login reads up to 256
groups), and marks the list truncated otherwise. On the way in, the CONNECT
request line is capped at 8 KiB and the whole header block at 64 KiB with a
10 s deadline: an overflow gets 431, deny reason `malformed_connect`, detail
`headers_too_large`. A token goes in one header, so a token near 16 KiB plus the
rest of a request's headers must still fit; keep `groupSearch` narrow rather
than relying on the caps.

Kubernetes guidance is prose only: run Dex from the upstream chart or your own
manifests with Postgres or CRD storage, give it a Secret for the values above
and an Ingress or Gateway serving the https issuer, and keep it off the
namespaces where agents run. This phase adds no manifest to `deploy/k8s`.

## 8. Running it locally

The dev stack is Dex plus a seeded OpenLDAP, from
`deploy/compose/docker-compose.identity.yml` with `config.dev.yaml`; the commands
below run against the L2 identity stack (`make e2e-identity-up`, which loads the
dev placeholders from `deploy/compose/dex/.env.example`).

Fetch a token for a seeded user with the password grant (dev only: it needs
`config.dev.yaml`). The script checks `aud` contains `warden`, `azp` is
`agent-harness` and `exp - iat` is 3600, and prints the decoded claims only:

```sh run
set -a; . deploy/compose/dex/.env.example; set +a
scripts/dex-token.sh alice | jq -c '{azp, groups: (.groups | sort), warden_in_aud: (.aud | index("warden") != null)}'
```

```text
{"azp":"agent-harness","groups":["eng","warden-admins"],"warden_in_aud":true}
```

Group claims per seeded user (LDAP `cn` values):

```sh run
set -a; . deploy/compose/dex/.env.example; set +a
for u in alice bob carol dave; do
  printf '%s ' "$u"
  scripts/dex-token.sh "$u" | jq -c '.groups | sort'
done
```

```text
alice ["eng","warden-admins"]
bob ["warden-editors"]
carol ["warden-viewers"]
dave ["eng"]
```

Dave has no role in `console.roles`, so a console login for dave fails with
`no_role`. The public CLI client can start a device login without a secret:

```sh run
curl -fsS http://localhost:5556/dex/device/code \
  -d client_id=warden-cli \
  -d 'scope=openid email profile groups offline_access audience:server:client_id:warden' |
  jq -c '{device_code: (.device_code != null), user_code: (.user_code != null)}'
```

```text
{"device_code":true,"user_code":true}
```

On a user machine the same flow is `warden identity login`; for the dev stack
the issuer is the loopback one:

```sh
warden identity login --issuer http://localhost:5556/dex --scopes audience:server:client_id:warden
warden identity status
warden identity token
```

`login` prints the verification URL and user code on stderr; `status` prints
issuer, sub, email, groups and expiry and never the token; `token` prints a
valid ID token on stdout and refreshes it when it is past two thirds of its
lifetime. Never paste its output into logs or issues. See the
[identity contract](identity-contract.md) for exit codes and the transport
rules.

`scripts/dex-token.sh` reads `DEX_TEST_PASSWORD` and `HARNESS_DEX_CLIENT_SECRET`
from the environment and `DEX_URL` (default `http://localhost:5556/dex`). A
container that runs it sets `DEX_URL=http://dex:5556/dex`, because `localhost`
is itself there.
