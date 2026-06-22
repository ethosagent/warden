# Warden

**An agent egress guardrail proxy.** Warden wraps an untrusted LLM agent runtime
so it is *structurally incapable* of reaching the internet except through a
mediating proxy that enforces allow/deny policy on every call and swaps
placeholder tokens for real secrets at the network edge.

## The core invariant

The wrapped agent has **no direct network route out**. The only path to the
internet is through Warden, enforced by the container/orchestration runtime —
not by asking the agent to behave. As a result the agent:

- **cannot exfiltrate data** — every destination is checked against a
  default-deny allowlist;
- **cannot make rogue calls** — anything off the allowlist is blocked at the TCP
  floor;
- **never holds a real secret** — it holds placeholders (e.g.
  `openai_secret_001`); the real credential is injected at the edge and never
  returns to the agent.

## Positioning

We are **agent-specific**, not a general egress firewall

If you run normal applications, a general-purpose egress proxy is a simpler fit.
If you run **agents**, Warden understands the protocols and threats agents
generate.

## Quickstart

```sh
# Build the single binary.
make build

# Run the full check gate (format, vet, lint, build, test+race, coverage).
scripts/check.sh

# Install git hooks once (pre-commit = fast, pre-push = full gate).
scripts/install-hooks.sh

# Generate the bake-once proxy CA the agent will trust (TLS termination).
scripts/gen-certs.sh

# Run the proxy against the example config (serving lands in M1).
go run ./cmd/proxy -config configs/config.example.yaml
```

Configuration shape is documented in
[`configs/config.example.yaml`](configs/config.example.yaml): a default-deny
`policy.allowlist` (domain + optional port), placeholder↔envVar `secrets`, cache
`ttl`, and `logging`.

## Deployment templates

Warden requires a container runtime so the isolation is structural — there is no
bare local-process mode. Templates encode the isolation:

- **Local dev** — `deploy/compose/` — agent + proxy sidecar on an internal-only
  network; the agent has no external route.
- **Kubernetes** — `deploy/k8s/` — sidecar manifest + default-deny egress
  `NetworkPolicy` (egress allowed only to the proxy).
- **EC2 / VM** — `deploy/vm/` — proxy as a systemd service or container on the
  instance; agent container with egress routed to the proxy.

## Layout

See [`AGENTS.md`](AGENTS.md) for the package map, build/test commands, and
conventions.

## License

[Apache-2.0](LICENSE).
