# 0003. Architecture rules use Go-native checks, not archcheck

- **Status:** Accepted as a decision. The checks themselves are not built yet (#349 is open), so until
  they land, reviewers check the rules by hand with `.agents/reviews/architecture.md`.
- **Source:** [#349](https://github.com/ethosagent/warden/issues/349), which supersedes the closed
  [#344](https://github.com/ethosagent/warden/issues/344).

## Context

#344 proposed archcheck. It has no Go support (an estimated 6–12 engineer-weeks of frontend work), and it
would add Node and npm to the pure-Go `scripts/check.sh` gate, breaking local/CI parity and adding
supply-chain surface.

## Decision

Write the rules once in `architecture.yaml` with stable IDs. Enforce them with golangci-lint
(`depguard`, `forbidigo`, `gomodguard`) through a generated config, plus an `internal/archtest` Go test
that runs under `go test ./...`. A baseline file records today's violations so the gate only tightens.

## Consequences

- No new toolchain in the gate; the same checks run locally and in CI.
- Rule IDs map onto archcheck's model if it gains Go support later.
- A review check that keeps finding the same problem should become one of these rules.
- The baseline is the only record of violations. The one standing exception is rule L7's
  `shared-repositories` list (#537): exact paths of shared infrastructure (the CP state DB, the clock
  port, the signer) that any repository may import. It is not a violation list, so it does not have to
  shrink, but adding an entry is a gates change: `tools/gatecheck` reports it as a widened allowance and
  only a maintainer's `gates-change-approved` label passes it.
