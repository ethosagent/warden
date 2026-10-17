# Roadmap conventions

How roadmap work is named, labelled and changed. Read this before editing
`tickets.json` or opening a roadmap issue by hand.

## One source of truth

`tickets.json` holds every feature and ticket. These are generated from it,
so never edit them by hand:

| Output | Command |
|---|---|
| `README.md`, `features/*.md`, `plan.html` | `go run docs/roadmap/gen.go docs` |
| GitHub epics and ticket issues | `go run docs/roadmap/gen.go issues -repo ethosagent/warden -phases 1,2,3,4 -update` |

`scripts/check.sh` runs `go run docs/roadmap/gen.go check`, which fails when
the data is invalid (unknown dependency, cycle, duplicate key) or a generated
file is stale. Text edited directly on a GitHub issue is overwritten by the
next `-update`; comments, assignees and open/closed state are kept.

Hand-written files: this one, `plan.template.html` (page layout),
`architecture.svg` (final design) and `_planning/handoff.md` (history).

## Hierarchy

```
Roadmap issue (pinned)
└── Epic: one per feature        e.g. [Epic] Verify user token
    └── Ticket: one PR each      e.g. [Verify user token 2/5] Extract, verify and strip identity…
```

Epics are sub-issues of the Roadmap issue; tickets are sub-issues of their
epic. Issues were created in build order, so lower numbers come first.

## Keys

Every ticket has a permanent key: `W-P<phase>-<CODE>-<NN>`.

- `W` is Warden; `P1`…`P5` is the phase.
- `CODE` is a short feature code (`VRFY` = Verify user token, `DEX` = Dex).
- `NN` is the ticket's order inside the feature, starting at `01`.

Keys never change and are never reused. If a ticket is split, the parts take
a suffix (`W-P2-WCA-04a`, `W-P2-WCA-04b`) so existing references stay valid.
Each issue body starts with a hidden `<!-- roadmap:KEY -->` marker; the
generator uses it to find the issue again, so don't remove it.

## Titles

- Ticket: `[<Feature> n/N] <action>`, where n is the ticket's position and N
  is the feature's ticket count. Start the action with a verb: "Add",
  "Record", "Extract".
- Epic: `[Epic] <Feature>`.

## Labels and milestones

| Label | Example | On |
|---|---|---|
| Phase name | `P1 · Who did it` | every epic and ticket |
| Feature | `feature:identity-verification` | the epic and its tickets |
| Area (component) | `area:worker`, `area:control-plane`, `area:identity`, `area:harness`, `area:integrations` | every epic and ticket |
| Type | `type:feature`, `type:test`, `type:docs`, `type:chore`, `type:spike` | tickets |
| Size | `size:S`, `size:M`, `size:L` | tickets |
| `epic` / `roadmap` | | epics / the Roadmap issue |

Each phase also has a milestone with the same name as its phase label, so
progress per phase shows as a percentage on the milestones page.

## Sizes

| Size | Working days, one engineer | Rule |
|---|---|---|
| S | 1–2 | |
| M | 3–5 | Split if it changes both the worker and the control plane |
| L | 6–10 | Always split before work starts |

## What every ticket must satisfy

- One PR, mergeable on its own, with main green.
- New behaviour ships behind a flag or default-off config, so merging changes
  nothing until it is switched on.
- `scripts/check.sh` passes, including the coverage gate.
- Acceptance criteria are covered by `test/harness` scenarios.
- A new external dependency ships a fake in `test/harness`.
- No secret, token or full request/response body in logs or test output.
- Default-deny and the core invariant in `AGENTS.md` are never weakened.

## Phases

| Phase | Name | Opened on GitHub |
|---|---|---|
| P1 | Who did it | yes |
| P2 | Proven identity | yes |
| P3 | Act as the user | yes |
| P4 | Agents everywhere | yes |
| P5 | Enterprise scale | later (add `5` to `-phases`) |

Phase 1 must be production-usable on its own. A phase is closed when the
"what works at the end" sentence in `README.md` is true on a real deployment.
