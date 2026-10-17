# Review rubrics

Warden-specific checklists for reviewing a change. People use them, the
`openai-reviewer` skill uses them (`openai-review --lens <name>`), and so does
the autonomous review stage. Each rubric covers one **lens**, so a reviewer
looks at one kind of risk at a time.

Rubrics hold the checks that need **judgement**. Anything a script can decide
belongs in `scripts/check.sh` instead: architecture rules, tests, harness
scenarios, the gates check. Each rubric lists what CI already covers, so
reviewers don't spend time on it.

| Lens | File | Check IDs | Use it when |
|---|---|---|---|
| Security invariants | [`security-invariants.md`](security-invariants.md) | `SEC-*` | Every change to `internal/`, `cmd/`, `deploy/` or `Dockerfile`. Required for `risk:critical`. |
| Architecture | [`architecture.md`](architecture.md) | `ARCH-*` | New packages, new interfaces, new dependencies, changes to wiring in `cmd/` or `internal/worker`. |
| Hot path | [`hot-path.md`](hot-path.md) | `HOT-*` | Changes under `internal/proxy`, `internal/policy`, `internal/scan`, `internal/mcp` or anything called per request. |
| Acceptance | [`acceptance.md`](acceptance.md) | `ACC-*` | Every PR that closes an issue. |
| Test quality | [`test-quality.md`](test-quality.md) | `TEST-*` | Every PR that adds or changes behaviour. |
| Red team | [`../playbooks/red-team.md`](../playbooks/red-team.md) | `RT-*` | Exploratory attack runs against a stack built from a PR (see the playbook's rules of engagement and reporting section). |

## Which lenses a PR needs

| Risk tier (see #354) | Lenses |
|---|---|
| `critical` | security-invariants, hot-path, acceptance, test-quality, and architecture if the shape changes |
| `normal` | acceptance, test-quality, and security-invariants if it touches a data path or secrets |
| `gates` | A human reviews. Agents don't review changes to the gates. |
| `low` (docs) | acceptance only |

## Finding format

Every lens reports findings in the same shape, so they can be deduplicated,
verified and counted:

```json
{
  "lens": "security-invariants",
  "rule": "SEC-4",
  "severity": "critical",
  "file": "internal/proxy/grpc.go",
  "line": 89,
  "issue": "the new header rewrite runs in runRequestStages only, so gRPC streams skip it",
  "evidence": "serveGRPCStream copies headers directly (grpc.go:89) and never calls runRequestStages",
  "suggestion": "apply the rewrite in serveGRPCStream too, and add an L1 scenario over HTTP/2"
}
```

- `rule` is the check ID from the rubric. Use `SEC-0`, `ARCH-0` and so on for
  a real problem the rubric doesn't list yet.
- `evidence` points at code, a test or command output. A finding without
  evidence is a question, not a finding.
- The `openai-review` script accepts `rule` and `evidence` as optional fields
  next to its usual output.

## Severity

| Severity | Meaning | Action |
|---|---|---|
| `critical` | Breaks the core invariant: egress bypass, a real secret reaching the agent, fail-open, an auth bypass | Block. Fix before merge. |
| `high` | A security weakness, data loss, or a broken acceptance criterion | Fix before merge. |
| `medium` | Real cost later: coupling, a missing test for a risky branch, avoidable per-request cost | Fix, or record why not. |
| `low` | Readability, naming, small cleanups | Optional. |

## How to review with a rubric

1. Read the linked issue's acceptance criteria first, then the diff.
2. Go through the rubric's checks in order. Skip the ones that clearly don't
   apply to this diff, but think about each one.
3. For each finding, write down the evidence. If you can't point at code, a
   test or output, ask instead of asserting.
4. Don't report what CI already decides (lint, format, coverage, architecture
   rules). If CI should have caught something and didn't, that's an `ARCH-0`
   or `TEST-0` finding about the gate.

## From review to rule

A check that keeps finding the same problem should become a deterministic one.
When the same `rule` ID is confirmed on two or more PRs, open an issue to
enforce it in CI: an architecture rule (#349), an invariant or harness
scenario (#350, #351), a lint rule, or a gates check (#354). Then mark the
check in its rubric as **covered by CI**, with a link.
