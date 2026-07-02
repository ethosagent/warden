# Demo — DLP class×destination egress (the recording asset)

This is the concrete, copy-pasteable version of the five-step DLP scenario from
`plan/Feat-DLP-Data-Classes.md` §D6. It is the **DLP recording asset** referenced
by `plan/Roadmap-Top3.md` ("PII → Zendesk allowed, PII → OpenAI blocked, an AWS
key redacted inline"). Run it against the standard control-plane compose recipe.

The one-line pitch it demonstrates: *the same customer record is allowed to your
CRM and blocked to an LLM provider, and an AWS key is stripped inline before it
ever leaves the boundary — decided per data class, per destination.*

> DLP is **restriction-only**. It can only further-restrict statically-allowed
> traffic; it never resurrects a denied destination. So every destination the
> agent touches below is also on the static allowlist.

---

## 0. Prereqs

From the repo root, generate the bake-once proxy CA (once):

```sh
OUT_DIR=deploy/compose/certs ./scripts/gen-certs.sh
```

## 1. The config (enforce mode)

The control plane serves policy + the `dlp:` block to the worker over
SettingsWire. Save this as `configs/config.dlp-demo.yaml` — it is the D2 example
made runnable. The three echo hosts stand in for **your Zendesk sandbox** and
**your webhook**; substitute your real ones freely.

```yaml
# configs/config.dlp-demo.yaml — served by the control plane
policy:
  # Static allowlist evaluates FIRST. DLP only restricts what is already allowed.
  allowlist:
    - domain: api.openai.com          # an LLM provider — PII must NEVER go here
    - domain: "*.zendesk.com"         # your sanctioned CRM — PII allowed here
    - domain: postman-echo.com        # runnable stand-in for the Zendesk sandbox
    - domain: httpbin.org             # runnable stand-in for your webhook
    - domain: github.com              # source code may go here
    - domain: "*.githubusercontent.com"

dlp:
  mode: enforce                       # off | monitor | enforce
  classes:
    credentials: { action: redact }   # global default: strip credentials inline
  rules:
    - class: "pii.*"                  # customer PII -> the CRM: allowed
      to: ["*.zendesk.com", "postman-echo.com"]
      action: allow
    - class: "pii.*"                  # customer PII -> LLM providers: blocked
      to: ["api.openai.com", "api.anthropic.com", "openrouter.ai"]
      action: block
    - class: source_code             # source code -> GitHub: allowed
      to: ["github.com", "*.githubusercontent.com"]
      action: allow
    - class: source_code             # source code -> anywhere else: blocked
      action: block
    - class: credentials             # credentials -> the webhook: redacted inline
      to: ["httpbin.org"]
      action: redact
```

Point the control plane at it by overriding the served-config mount in
`deploy/compose/docker-compose.yml` (the `control-plane` service) — change:

```yaml
    volumes:
      - ../../configs/config.dlp-demo.yaml:/etc/warden/config.yaml:ro
```

Then bring the stack up (control plane + worker + an isolated agent container):

```sh
WARDEN_CP_TOKEN=dev-token \
docker compose -f deploy/compose/docker-compose.yml up -d
```

- Fleet dashboard (control plane): https://localhost:7070/dashboard/ (trust the proxy CA)
- Worker-local dashboard: http://localhost:9090/dashboard/

Give the demo agent `curl` (the stand-in image is bare alpine):

```sh
docker compose -f deploy/compose/docker-compose.yml exec agent apk add --no-cache curl
```

`CA=/etc/warden/certs/proxy-ca.crt` — the agent trusts the proxy CA at this path.

## 2. The five steps

Run each from the isolated agent. It has **no internet route except the proxy**.

### Step A — customer PII → LLM provider: **BLOCKED (403)**

```sh
docker compose -f deploy/compose/docker-compose.yml exec agent \
  curl -sS --cacert /etc/warden/certs/proxy-ca.crt -o /dev/null -w "%{http_code}\n" \
  -X POST https://api.openai.com/v1/chat/completions \
  -H 'content-type: application/json' \
  -d '{"customer":{"name":"Jane Roe","email":"jane.roe@example.com","card":"4242 4242 4242 4242"}}'
# => 403
```

**Expected event:** `classes=[pii.contact, pii.financial]`, `action=block`,
`rule=<the pii→LLM block rule>`, decision `deny`. Same record, wrong destination.

### Step B — the same PII → sanctioned CRM: **ALLOWED (forwarded)**

```sh
docker compose -f deploy/compose/docker-compose.yml exec agent \
  curl -sS --cacert /etc/warden/certs/proxy-ca.crt -o /dev/null -w "%{http_code}\n" \
  -X POST https://postman-echo.com/post \
  -H 'content-type: application/json' \
  -d '{"customer":{"name":"Jane Roe","email":"jane.roe@example.com","card":"4242 4242 4242 4242"}}'
# => 200 (forwarded)
```

**Expected event:** `classes=[pii.contact, pii.financial]`, `action=allow` — the
classes are still recorded, but the sanctioned destination is permitted.

### Step C — an AWS key → webhook: **REDACTED inline (forwarded)**

```sh
docker compose -f deploy/compose/docker-compose.yml exec agent \
  curl -sS --cacert /etc/warden/certs/proxy-ca.crt \
  -X POST https://httpbin.org/post \
  -H 'content-type: application/json' \
  -d '{"config":{"aws_access_key_id":"AKIAIOSFODNN7EXAMPLE"}}' | grep -o 'REDACTED[^"]*\|AKIA[0-9A-Z]*'
# => REDACTED:credentials     (and NO AKIA... line: the key never left the boundary)
```

`httpbin.org/post` echoes the exact body it received. The echo shows
`[REDACTED:credentials]` where the key was — **proof the AKIA value never
crossed the wire**. **Expected event:** `classes=[credentials]`, `action=redact`,
`rule=<the credentials redact rule>`, decision `allow`.

## 3. Read the dashboard DLP panel

Open the fleet dashboard (https://localhost:7070/dashboard/) → **Analytics** →
the **"DLP — outbound data classes"** panel:

- **Summary row:** total DLP events + the by-action breakdown as colored counts —
  `allow` (green), `block` (red), `redact` (amber), `monitor` (neutral).
- **By-class list:** `pii.contact`, `pii.financial`, `credentials` with counts.
- **Class × destination matrix** — the flagship view. Rows are data classes,
  columns are destinations, each cell is the color-coded action + count:

  |                 | api.openai.com | postman-echo.com | httpbin.org |
  |-----------------|:--------------:|:----------------:|:-----------:|
  | `pii.contact`   | **block** (red) | **allow** (green) |             |
  | `pii.financial` | **block** (red) | **allow** (green) |             |
  | `credentials`   |                |                  | **redact** (amber) |

  Empty cells mean no data for that pair. A tiny legend maps colors to actions.
  When the destination count exceeds the top-N cap, the panel shows an
  "…and M more" note rather than silently dropping columns.

That matrix — pii→CRM green, pii→openai red, credentials→webhook amber — is the
single screen that says *"what kinds of data are my agents sending where."*

## 4. Empty state

With `dlp.mode: off` (or no DLP events yet) the panel shows a friendly
*"No DLP activity yet — enable dlp in monitor mode to see outbound data classes
here"* rather than an empty grid. Start in `monitor` mode for the zero-risk
first-hour wedge: nothing is blocked or redacted, but every outbound data class
lights up on the matrix.

## 5. Tear down

```sh
docker compose -f deploy/compose/docker-compose.yml down -v
```

---

**No content ever leaves the boundary in the telemetry.** Events, logs, and the
dashboard carry only class names, actions, destination domains, and counts —
never the matched bytes, never offsets. The redaction echo in Step C is the only
place you see the *absence* of the secret, which is the point.
