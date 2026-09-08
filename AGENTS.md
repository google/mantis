# Agent Rules

## Before committing

**Always run `pre-commit run --all-files` before creating or amending a
commit.**

This ensures all markdown files conform to the pinned mdformat 0.7.21 formatter
(`--number --wrap 80` with gfm + frontmatter plugins). The hook installs its own
isolated venv — do not run local `mdformat` directly.

If the hook modifies files, stage the changes and amend your commit.

## ADK Invariant Architecture & Deterministic Gates

Security invariants (INV-1 through INV-6) are enforced deterministically by the
Google ADK Python runtime, Pydantic schemas, and tool wrappers rather than
prompt fences:

- **INV-1 & INV-2 (Evidence & Re-attack)**: Enforced by `sandbox_tools.py`
  reached-sink sentinel verification and `schemas.py` validation. Objective
  third-party re-attack and strict separation-of-duties role separation are
  orchestrated by `mantis-patch` to eliminate self-grading confirmation bias.
- **INV-3 (Regression Tracking)**: Enforced by finding lineage schemas and
  snapshot-match rules.
- **INV-4 (Target Immutability & Host Boundary)**: Enforced by
  `research_tools.py` path bounds checks (strictly read-only on the host target
  checkout; all mutations constrained to `workspace/` or isolated guest
  sandboxes).
- **INV-5 (State Resumption & Monotonic Lineage)**: Enforced by
  `BudgetController` checkpointing and `database.py` monotonic status
  preservation across process restarts via `--resume <run_id>`. Upstream
  repository synchronization and environment provisioning are managed externally
  before resuming Mantis.
- **INV-6 (Fail-Safe Backward Compatibility)**: Enforced by schema defaults and
  fail-closed degradation gates.

Skills must remain clean, dense domain guides focused on vulnerability analysis,
attack vectors, and remediation. Do not re-embed bash Git commands, manual file
locking, or ASCII block fences in skill prompts. All invariants are verified by
`reference/tests/test_adk_invariants.py`.

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
   back to fresh patch generation, verified by re-attack verification).

`mantis-patch/references/patch_rebasing.md` qualifies (pure mechanics, no
invariant restated, fails safe to Phase-1). Do not extract content that restates
a crown-jewel invariant — trim it inline instead.

## Structural index spec

The structural index spec lives in **one canonical location**:
`mantis-structural-index/SKILL.md`. Locator resolution instructions and semantic
unit definitions appear only in this canonical skill.
