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

## Reference files

Skills may split on-demand content into `references/` subdirectories (e.g.
`mantis-calibrate/references/calibration_rules.md`). Before committing, verify
that every `references/*.md` link target in a `SKILL.md` file exists on disk and
is tracked by git (`git ls-files --error-unmatch <path>`).

### Extraction criteria

Extract a block into a `references/` file only if ALL three hold:

1. **Off the fail-closed safety-critical path** — the extracted content is not
   the sole authority for a security-critical invariant (e.g. the
   `VERIFIED_SECURE => reattack_status = failed_to_bypass` gate).
2. **Restates no invariant** — the extracted content does not restate any rule
   that is also stated in the SKILL.md (no invariant may appear in both a
   SKILL.md and its reference; if a rule must be referenced, state it once and
   point to it).
3. **Clean fail-safe fallback** — if the reference cannot be loaded, the skill
   falls back to safe behavior without the reference (e.g. patch rebasing falls
   back to fresh patch generation, verified by Block G).

`mantis-patch/references/patch_rebasing.md` qualifies (pure mechanics, no
invariant restated, fails safe to Phase-1). Do not extract content that restates
a crown-jewel invariant — trim it inline instead.
