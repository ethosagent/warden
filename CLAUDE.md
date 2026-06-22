# CLAUDE.md

This file exists only so Claude Code finds project instructions under its
conventional filename. **The canonical, tool-agnostic instructions live in
[`AGENTS.md`](AGENTS.md)** — read that file.

Do not duplicate guidance here; keeping a single source (`AGENTS.md`) avoids
drift. If a rule needs to change, change it in `AGENTS.md`.

## Skills

Project skills are stored tool-agnostically under [`.agents/skills/`](.agents/skills/).
`.claude/skills` is a symlink to that directory so Claude Code discovers them
without a second copy. Add or edit skills in `.agents/skills/`.
