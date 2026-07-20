# 3-Way Patch Rebasing (Phase 2 Incremental Efficiency)

> **Load trigger:** This reference is loaded when `/mantis-patch` determines
> that ALL reachability conditions for 3-way patch rebasing are satisfied (see
> `mantis-patch/SKILL.md` Step 2 for the inline reachability gate). The
> procedure below is the 3-way merge mechanics and success/failure handling.
>
> **Safe fallback:** If the agent forgets to load this reference, the correct
> behavior is to fall back to fresh patch generation (Phase-1 behavior). This is
> documented in the SKILL.md guardrail.

## How: 3-Way Merge Mechanics

- **How:** Locate the prior pass's `patch_diff` from the archived finding (the
  finding JSON in `workspace/archive/findings_pass_<N-1>/`). `patch_diff` is a
  unified DIFF, not a whole file. Reconstruct the three 3-way-merge inputs as
  SCRATCH copies (never edit the archived copies or either snapshot in place):
  - `base` = the PRIOR snapshot's unpatched version of the file, copied to a
    scratch path (requires the prior snapshot dir on disk — see the reachability
    check; if absent, fall back to fresh generation).
  - `ours` = a copy of `base` with the archived `patch_diff` applied
    (`patch <base_copy> < patch_diff`, or `git apply`). This reconstructs the
    prior PATCHED file. If the diff does not apply cleanly to `base`, fall back
    to fresh generation.
  - `theirs` = the CURRENT snapshot's unpatched version of the same file, copied
    to a scratch path. Then run
    `git merge-file -p <ours> <base> <theirs> > <result>` — the `-p` flag writes
    the merged result to stdout so it does NOT overwrite `<ours>` in place
    (argument order is ours, base, theirs). If `git` is unavailable, use
    `diff3 -m <ours> <base> <theirs> > <result>` or any 3-way merge tool that
    writes to a SEPARATE output. If the merge produces no conflict markers,
    `<result>` is the current file with the fix rebased onto it. If no 3-way
    merge tool is available, fall back to fresh patch generation (Phase-1
    behavior).

## When Rebasing SUCCEEDS / FAILS / Guardrail

- **When rebasing SUCCEEDS** (clean 3-way merge): use the rebased patch as the
  starting point for verification. Still run Block G (unpatched baseline +
  post-patch gate) to confirm the rebased patch is correct. Mark the finding
  with a history note `patch-rebased-from: pass_<N-1>`.

- **When rebasing FAILS** (merge conflict, file deleted, file renamed beyond
  recognition, or the patched function no longer exists): fall back to
  generating a fresh patch from scratch (Phase-1 behavior). Never use a
  conflicting or ambiguous rebased patch.

- **Guardrail:** On ANY uncertainty, fall back to Phase-1 patch generation.
  Never apply a rebased patch that has unresolved conflicts or that touches code
  unrelated to the original fix.
