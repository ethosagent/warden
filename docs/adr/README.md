# Architecture decision records

Short records of decisions that shape Warden's boundaries, with the reason, so
agents and contributors don't undo them without seeing why.

**Read the relevant ADR before changing that area. Write a new ADR when a change moves
a boundary** (a layer, a plane, where data or credentials live, a public route prefix,
a dependency rule). Copy [`template.md`](template.md), take the next number, and link the
issue or PR where the decision was made.

| # | Decision | Status |
|---|---|---|
| [0001](0001-data-plane-split-and-repository-layer.md) | Data plane split into engine, decision stages and side calls; repository layer for the control plane | Proposed |
| [0002](0002-per-user-credentials-control-plane-only.md) | Per-user credentials live only in a control-plane store | Proposed |
| [0003](0003-go-native-architecture-checks.md) | Architecture rules use Go-native checks, not archcheck | Accepted |
| [0004](0004-admin-routes-under-dashboard-api.md) | Admin routes live under `/dashboard/api/*`; `/api/` is reserved | Accepted |
| [0005](0005-machine-events-outside-admin-audit.md) | Machine events go to their own tables and log streams | Proposed |
| [0006](0006-single-module-static-binary-pure-go-sqlite.md) | One Go module, one static binary, pure-Go SQLite, no CGo | Accepted |

Statuses: **Proposed** (decided, but the code does not follow it yet), **Accepted** (the code
follows it), **Superseded by NNNN**.
