---
name: openai-reviewer
description: Run OpenAI Codex CLI as Warden's code reviewer. Code is written by Claude and reviewed by Codex — never review your own code. Invoke for ALL review requests in this project ("review", "check it", "look it over", "code review") and any time non-trivial Go code has been written.
allowed-tools: Bash(openai-review *), Bash(*/openai-review *)
---

# OpenAI Code Review (Warden)

On-demand, two-pass review. There is **no Stop hook** wired in this repo — run it
when asked, or after writing non-trivial code.

## Routing rule (hard)

**All reviews go through this skill.** When the user asks for any kind of review —
explicit ("review this", "code review") or implicit ("check it", "look it over") —
go through the two-pass flow below.

## Two-pass review flow

**Pass 1 — Self-review (Claude, fast):**
Before calling Codex, scan your own diff for things you would have caught yourself:

- Typos, dead code, unused imports/variables.
- Format / vet / lint: run `scripts/check.sh` (or at minimum `gofmt -l .`,
  `go vet ./...`, `golangci-lint run`) when changes are non-trivial.
- Tests missing for new behavior — and the **must-test invariants** still hold
  (default-deny blocks non-allowlisted; secrets logged by reference only, never
  raw; headers only, no full bodies; cache stale-on-failure vs. manual hard-fail).
- `AGENTS.md` rule violations: bypassing the three core interfaces, business logic
  in `cmd/`, a CGo SQLite driver, speculative `pkg/`, error handling for impossible
  cases, abstractions for single-use code.

Fix everything you find. Only then move to Pass 2.

**Pass 2 — Codex review (architectural, 5-year horizon):**
Invoke `openai-review`. Codex looks for what you cannot easily see in your own
work: brittle abstractions, hidden coupling, API choices that will be hard to
evolve, premature flexibility, things that rot under scale or team turnover. For a
security tool this matters doubly — a leaky abstraction here is a future CVE.

The split exists because LLM self-review is unreliable for the things you wrote
yourself. Pass 1 catches mechanical issues; Pass 2 brings an outside perspective.

> **Codex CLI required.** If `codex` is not installed, `openai-review` returns a
> `{"verdict":"error",...}` and Pass 2 is skipped — do Pass 1 and tell the user
> Codex is unavailable. Install the Codex CLI to enable Pass 2.

## Style

Reviews run in the voice of Linus Torvalds, focused on what will break in 5 years:
brittle abstractions, hidden coupling, hard-to-evolve APIs, cleverness that
obscures intent, speculative generality. The script bakes this into every call.

## Modes

`openai-review` defaults to `uncommitted` if no mode is given.

| Mode | When to use |
|---|---|
| `uncommitted` | Active coding — staged + unstaged changes (default) |
| `last-commit` | Review the latest commit only |
| `against-main` | Whole branch + uncommitted vs. main |
| `against-origin` | Unpushed commits vs. origin |

Add `--focus <security|performance|correctness|style|test>` to narrow scope.
For Warden, `--focus security` is the highest-value lens.

## Acting on findings

Codex returns JSON. Apply judgment — not every finding is correct.

| Severity | Action |
|---|---|
| `critical`, `high` | Fix |
| `medium` | Judgment call — fix unless it conflicts with project rules |
| `low` | Usually skip; surface to user only if relevant |

**Project rules in `AGENTS.md` take precedence over Codex.** If Codex demands a
change that violates an explicit project rule (error handling for impossible
scenarios, abstractions for single-use code, speculative flexibility, weakening
default-deny or logging hygiene), ignore it and explain why in one line.
