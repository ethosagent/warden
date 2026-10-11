# Architecture (`ARCH-*`)

Warden's goal is that every part can be replaced: core logic stays in the
domain, every external system sits behind an interface, and wiring happens in
one place. This lens checks that a change keeps that shape. The full model
and its rule IDs are in #349. The conventions are in
[`AGENTS.md`](../../AGENTS.md).

## Already covered by CI

- gofmt, vet and golangci-lint.
- Once #349 lands: layer and zone import rules, banned calls (`os.Environ`,
  `http.DefaultClient`, signing outside signer adapters), `json:"-"` on
  control-plane config fields, and "every package fits a layer". Until then,
  check those by hand with the checks below.

## The model in one paragraph

**Control plane:** domain (pure logic and the interfaces it needs) →
repository (`adapters/`, the only code that talks to databases, networks and
SDKs) → transport (HTTP handlers, no business logic) → assembly (`cmd/`,
picks adapters from config). **Data plane:** the *engine* (listener, TLS,
dialer, forward, relay) moves bytes; *decision stages* are pure functions
over request metadata; *side calls* (control plane, secrets, analytics,
judge) go through interfaces and must be cached, async or bounded.
Dependencies only point down.

## Checks

**ARCH-1 Logic lives in the domain, not in transport or `cmd/`.**
Handlers parse, authorise, call a service and map the response. `cmd/` parses
flags, loads config and calls assembly. Decisions, rules and state changes
belong in a domain package where they can be tested without HTTP.

**ARCH-2 External systems sit behind an interface the domain owns.**
A new database, HTTP API, cloud SDK, IdP, notifier or process launch goes
through an interface declared next to the code that *uses* it, implemented
in an adapter. Look for SDK or `database/sql` imports outside adapters, and
interfaces declared next to their only implementation.

**ARCH-3 Imports point down.**
No new edge from a lower layer to a higher one, and no new import between the
two assemblies. Two known edges point the wrong way today (#349): `analytics` →
`mcp/gateway`, and `controlplane` → `worker`. Don't add more, and don't build
on these.

**ARCH-4 The data plane keeps its split.**
Networking for proxied traffic stays in the engine (`internal/proxy` listener,
TLS, `forward`, `relayResponse`, streams). A new stage decides, it doesn't do
I/O. A new side call from the request path goes through an interface, with a
timeout and a defined failure result (see `SEC-5`).

**ARCH-5 New behaviour is a new stage, not an edit to a neighbour.**
`runRequestStages` is an ordered list. A feature that adds a decision should
add a stage with one job, not grow `swapSecrets` or `forward`. Check the
order: scans before `swapSecrets`, nothing that logs after it.

**ARCH-6 Swappable by config, with fakes.**
A new adapter is chosen by a config `backend:` value that's validated at
startup, with the safe or local option as default. Each interface has a
hand-written fake in `test/fakes` (or the harness from #350) and, for stores,
a shared conformance test that every adapter runs.

**ARCH-7 No package-level state.**
No mutable globals, no `init()` that registers things, no singletons.
Constructors take their dependencies as parameters.

**ARCH-8 Wire formats are versioned.**
Anything sent between worker and control plane, written to a log stream or
stored for later (policy wire, events, decision logs, tokens) has a version
and a schema or golden test. Readers ignore unknown fields, so older workers
keep working.

**ARCH-9 Interfaces are small and named for what the caller needs.**
A handful of methods, named from the caller's side. A wide interface that
mirrors one implementation makes the next implementation hard to write.

**ARCH-10 No speculative structure.**
No `pkg/`, no abstraction with one user, no options nobody sets, no plugin
system for a single case. `AGENTS.md` rules win over "might need it later".

**ARCH-11 Dependencies are justified.**
A new third-party module needs a reason in the PR, a maintained upstream and
a license compatible with Apache-2.0. Prefer the standard library. No CGo,
because Warden ships as one static binary (`modernc.org/sqlite` for SQLite).

## Out of scope for this lens

Security bugs inside a correctly shaped design (`SEC-*`), and per-request
cost (`HOT-*`).
