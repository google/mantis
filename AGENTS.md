# Agent Rules

## Before committing

**Always run `pre-commit run --all-files` before creating or amending a
commit.**

This ensures all markdown files conform to the pinned mdformat 0.7.21 formatter
(`--number --wrap 80` with gfm + frontmatter plugins). The hook installs its own
isolated venv — do not run local `mdformat` directly.

If the hook modifies files, stage the changes and amend your commit.

## Verbatim blocks

Blocks A/B/C/D/E/F/G are wrapped in ```` ``` ```` fences and must stay
**character-identical** across all skills. Never insert content *inside* their
fences — add notes *after* the closing ```` ``` ```` instead.
