---
name: add-adapter
description: Add a new implementation of an external dependency (store, secret backend, notifier, IdP) behind an interface selected by a backend config key. Use when Warden must talk to a new outside system.
---

# Add an adapter

Rules live in [`AGENTS.md`](../../../AGENTS.md); checks in
[`architecture`](../../reviews/architecture.md) (`ARCH-1`, `ARCH-2`, `ARCH-6`, `ARCH-7`, `ARCH-9`,
`ARCH-11`), [`security-invariants`](../../reviews/security-invariants.md) (`SEC-3`, `SEC-6`, `SEC-12`)
and [`test-quality`](../../reviews/test-quality.md) (`TEST-5`). Read [ADR 0001](../../../docs/adr/0001-data-plane-split-and-repository-layer.md)
and [ADR 0003](../../../docs/adr/0003-go-native-architecture-checks.md) first.

## Steps

1. **Declare the interface in the domain** that uses it, small and named for what the caller needs
   (`ARCH-9`). Document the logging rule on it (by reference only, never raw values).
2. **Write the conformance tests first.** Run the same behaviour cases against the fake and the new
   adapter. Today these are plain tests per implementation; a shared exported suite is planned
   (#349, rule S2).
3. **Implement the adapter.** Depend on the interface and the SDK or client only. Outbound HTTP uses
   the SSRF-safe dialer (`SEC-6`). Never log raw secrets or bodies (`SEC-3`). Prefer a small
   client interface over importing an SDK (`ARCH-11`), as `AWSSecretsClient` does.
4. **Add a fake** in `test/fakes/` (or beside the interface) so domain tests never use the network.
5. **Select by config.** Add a `backend:` value (constant, parse, `validate…` that rejects unknown
   values at startup, safe/local default). See `add-config-key`.
6. **Wire it in one place.** A constructor that switches on the validated backend; `cmd/` only calls
   it. No package-level state or `init()` registration (`ARCH-7`).
7. Run `scripts/check.sh`.

## Where the layout is today

`adapters/<x>/` directories and the Go-native layer checks (#349) do not exist yet. Existing
adapters sit in the domain package. Follow the interface/selection/fake pattern now, and put new
adapters under `internal/<domain>/adapters/<x>/` once #349 lands. Do not add more cross-package
wiring in `internal/worker` or `internal/controlplane`; that is known drift (#349).

## Worked example: `SecretStore`

- Interface: `SecretStore` in `internal/secrets/store.go` (by-reference logging rule in its doc).
- Implementations: `NewEchoStore` (`echo.go`, the fake-like local one), `NewAWSSecretStore` over the
  small `AWSSecretsClient` interface (`aws_store.go`, `aws.go`).
- Selection: `SecretBackendEnv|Echo|AWS` in `internal/config/secretstore.go`; `validateSecretStore`
  rejects unknown backends at startup; empty resolves to `env`.
- Wiring: `controlplane.NewSecretStore` (`internal/controlplane/secrets.go`) and `newSecretFetcher`
  (`internal/worker/worker.go`). `cmd/proxy/controlplane.go` only calls the constructor and fails fast.
