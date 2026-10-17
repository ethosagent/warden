# Skills

Tool-agnostic home for this project's agent **skills**. This is the single
source of truth; tool-specific directories point here rather than duplicating
content (e.g. `.claude/skills` is a symlink to this folder).

## Layout

Each skill is its own directory containing a `SKILL.md`:

```
.agents/skills/
└── <skill-name>/
    └── SKILL.md        # frontmatter (name, description) + instructions
```

A `SKILL.md` begins with YAML frontmatter:

```markdown
---
name: <skill-name>
description: <one line — when this skill should be used>
---

<instructions for the skill>
```

## Conventions

- Keep skills tool-agnostic. Anything Claude-Code-specific that cannot live here
  belongs in the tool's own config, not in a skill body.
- Reference repo files by relative path so the skill works from any agent.
- The project's build/test/convention rules live in [`AGENTS.md`](../../AGENTS.md);
  skills should defer to it rather than restating it.

## Skills

| Skill | Use it to |
|---|---|
| [`add-request-stage`](add-request-stage/SKILL.md) | add a decision stage to the HTTP request path |
| [`add-adapter`](add-adapter/SKILL.md) | add an implementation behind an interface, chosen by a `backend:` key |
| [`add-config-key`](add-config-key/SKILL.md) | add a config key with default, validation and docs |
| [`add-control-plane-route`](add-control-plane-route/SKILL.md) | add a control-plane or dashboard HTTP route |
| [`harness-scenario`](harness-scenario/SKILL.md) | add a fake and a scenario to the L1 test harness |
| [`openai-reviewer`](openai-reviewer/SKILL.md) | review code with the Codex CLI and the review rubrics |

Each task skill points at the review rubrics in [`../reviews/`](../reviews/README.md) and the
decisions in [`docs/adr/`](../../docs/adr/README.md).
