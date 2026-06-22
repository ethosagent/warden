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

No skills are defined yet — add the first one as `<skill-name>/SKILL.md`.
