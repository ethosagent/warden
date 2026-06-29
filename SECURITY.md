# Security Policy

Warden is a security boundary: it MITMs an agent's egress traffic and holds
real credentials. We take vulnerability reports seriously and ask that you
report them privately so users can be protected before details are public.

## Supported versions

Warden is pre-1.0. Security fixes are applied to the latest tagged release and
to `main`. Older tags do not receive backports. Pin to a tagged release and
upgrade promptly when a security release is published.

| Version | Supported |
| ------- | --------- |
| latest release / `main` | ✅ |
| any older tag | ❌ (upgrade) |

## Reporting a vulnerability

**Do not open a public GitHub issue for security problems.**

Use **GitHub Security Advisories** (the private reporting channel) for this
repository:

> Repo → **Security** tab → **Report a vulnerability**

This opens a private advisory visible only to you and the maintainers.

Please include, where you can:

- A description of the issue and its security impact (e.g. policy bypass,
  secret disclosure, fail-open behaviour, log leakage).
- The Warden version / commit and how Warden was deployed (sidecar, compose,
  VM).
- Reproduction steps or a proof-of-concept.
- Any suggested remediation.

If a credential, token, or other secret is exposed in your report, redact it.

## What to report

Issues that undermine Warden's core invariants are highest priority:

- A wrapped agent obtaining a **raw secret value** it should never hold.
- An egress path that **bypasses default-deny** (a destination reached without
  matching the allowlist).
- A path that **fails open** instead of closed (the LLM judge, non-TLS, or any
  error path allowing traffic that should be denied).
- A **raw secret value or full request/response body** appearing in logs,
  metrics, traces, or the analytics store.

## Response expectations

This is a community-maintained open-source project, not a commercial product
with an SLA. As a best-effort target:

- **Acknowledgement:** within 5 business days.
- **Triage / severity assessment:** within 10 business days.
- **Fix & coordinated disclosure:** timeline agreed with the reporter based on
  severity; we aim to publish a fix and advisory together.

We are glad to credit reporters in the advisory unless you prefer to remain
anonymous.
